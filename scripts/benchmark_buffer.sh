#!/usr/bin/env bash
# Benchmark SOCKSv5 proxy throughput for different buffer sizes.
#
# - Builds the proxy with multiple BUFFER_SIZE values (CFLAGS_EXTRA="-DBUFFER_SIZE=<n>").
# - Serves local files via a Python HTTP server.
# - Downloads each file directly and through the proxy, timing with curl.
# - Appends results to a CSV for later plotting.
#
# Usage:
#   scripts/benchmark_buffer.sh [output.csv]
# Environment overrides:
#   BUFFER_SIZES="512 1024 ..."   # list of buffer sizes in bytes
#   FILE_SIZES_MB="1 2 4 8 ..."   # list of file sizes in MiB
#   REPEATS=5                     # how many runs per combination
#   HTTP_PORT=8001
#   SOCKS_PORT=1080
#   PROXY_USER="foo:bar"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_CSV="${1:-${REPO_ROOT}/buffer_benchmark.csv}"
# Default: moderate sweep (bytes) to reduce run time/errors; override with BUFFER_SIZES env.
BUFFER_SIZES=${BUFFER_SIZES:-"512 4096 8192 16384 32768 65536 96000 128000 192000 256000 384000 512000 640000 1048576"}
FILE_SIZES_MB=${FILE_SIZES_MB:-"1 2 4 8 16 32 64 128"}
REPEATS=${REPEATS:-5}
HTTP_PORT=${HTTP_PORT:-8001}
SOCKS_PORT=${SOCKS_PORT:-1080}
PROXY_USER=${PROXY_USER:-foo:bar}

FILES_DIR="${REPO_ROOT}/.bench_http_files"
LOG_DIR="${REPO_ROOT}/.bench_logs"
mkdir -p "${FILES_DIR}" "${LOG_DIR}"

HTTP_PID=""
PROXY_PID=""

cleanup() {
  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

generate_files() {
  for mb in ${FILE_SIZES_MB}; do
    local path="${FILES_DIR}/file_${mb}MiB.bin"
    if [[ ! -f "${path}" ]] || [[ "$(stat -c%s "${path}")" -ne $((mb * 1024 * 1024)) ]]; then
      echo "Generating ${mb} MiB file..."
      dd if=/dev/zero of="${path}" bs=1M count="${mb}" status=none
    fi
  done
}

start_http_server() {
  echo "Starting local HTTP server on port ${HTTP_PORT}..."
  python3 -m http.server "${HTTP_PORT}" --bind 127.0.0.1 --directory "${FILES_DIR}" \
    >"${LOG_DIR}/http_server.log" 2>&1 &
  HTTP_PID=$!
  sleep 1
}

build_proxy() {
  local buf_size=$1
  echo "Building proxy with BUFFER_SIZE=${buf_size}..."
  (cd "${REPO_ROOT}" && make clean all CFLAGS_EXTRA="-DBUFFER_SIZE=${buf_size}" \
    >"${LOG_DIR}/build_${buf_size}.log" 2>&1)
}

start_proxy() {
  local buf_size=$1
  echo "Launching proxy on port ${SOCKS_PORT}..."
  "${REPO_ROOT}/build/bin/socks5d" -u "${PROXY_USER}" -p "${SOCKS_PORT}" \
    >"${LOG_DIR}/proxy_${buf_size}.log" 2>&1 &
  PROXY_PID=$!
  sleep 1
}

measure_download() {
  local url=$1
  local mode=$2
  local curl_args=("-s" "-w" "%{time_total}" "-o" "/dev/null")
  if [[ "${mode}" == "proxy" ]]; then
    curl_args+=(--socks5-hostname "127.0.0.1:${SOCKS_PORT}" --proxy-user "${PROXY_USER}")
  fi
  local attempt duration trimmed
  for attempt in {1..3}; do
    duration=""
    if duration="$(curl "${curl_args[@]}" "${url}")"; then
      # strip whitespace/newlines that sometimes sneak in
      trimmed="$(printf "%s" "${duration}" | tr -d '[:space:]')"
      if [[ "${trimmed}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        printf "%s" "${trimmed}"
        return 0
      fi
    fi
    sleep 0.2
  done
  echo "warning: curl failed for ${url} (${mode})" >&2
  printf ""
}

write_csv_header() {
  if [[ ! -f "${OUTPUT_CSV}" ]]; then
    echo "buffer_size_bytes,file_size_bytes,throughput_mbps,mode,run" >"${OUTPUT_CSV}"
  fi
}

generate_files
start_http_server
write_csv_header

for buf_size in ${BUFFER_SIZES}; do
  build_proxy "${buf_size}"
  start_proxy "${buf_size}"

  for mb in ${FILE_SIZES_MB}; do
    file_path="${FILES_DIR}/file_${mb}MiB.bin"
    file_bytes=$((mb * 1024 * 1024))
    url="http://127.0.0.1:${HTTP_PORT}/$(basename "${file_path}")"

    for mode in direct proxy; do
      for run in $(seq 1 "${REPEATS}"); do
        duration="$(measure_download "${url}" "${mode}")"
        if [[ -z "${duration}" || ! "${duration}" =~ ^[0-9.]+$ ]]; then
          echo "Skipping measurement due to curl error (buffer=${buf_size}, file=${mb}MiB, mode=${mode}, got='${duration}')" >&2
          continue
        fi
        throughput=$(awk -v bytes="${file_bytes}" -v dur="${duration}" 'BEGIN { if (dur <= 0) { exit 1 } printf "%.6f", (bytes*8)/dur/1e6 }' || true)
        if [[ -z "${throughput}" ]]; then
          echo "Skipping measurement due to invalid duration (buffer=${buf_size}, file=${mb}MiB, mode=${mode}, got='${duration}')" >&2
          continue
        fi
        echo "${buf_size},${file_bytes},${throughput},${mode},${run}" >>"${OUTPUT_CSV}"
        echo "buf=${buf_size}B file=${mb}MiB mode=${mode} run=${run} -> ${throughput} Mbps"
      done
    done
  done

  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
    PROXY_PID=""
  fi
done

echo "Done. Results at ${OUTPUT_CSV}"
