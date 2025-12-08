#!/usr/bin/env python3
"""
Plot buffer-size benchmarks for the SOCKS5 proxy.

Expected CSV columns (one row per download run):
- buffer size in bytes: one of buffer_size_bytes, buffer_bytes, buffer_size, buf_size, buf
- file size in bytes:   one of file_size_bytes, file_bytes, file_size
- throughput in Mbps:   one of throughput_mbps, bandwidth_mbps, speed_mbps, mbps
Optional columns:
- mode/proxy flag: mode, proxy, with_proxy, use_proxy (bool/0-1/strings)
- elapsed seconds (used if throughput is missing): duration_seconds, seconds, time_seconds, elapsed

The script aggregates runs by buffer size + file size + mode, averages throughput,
and produces:
1) One plot per file size comparing buffer size vs throughput (with/without proxy).
2) A plot with the average throughput across all file sizes for each buffer size.

Usage:
  python3 scripts/plot_buffer_benchmark.py results.csv --out plots
"""

import argparse
import sys
from pathlib import Path
from typing import Iterable, Optional

import matplotlib.pyplot as plt
import pandas as pd


def pick_column(columns: Iterable[str], candidates: Iterable[str], required: bool = True) -> Optional[str]:
    """Return the first matching column (case-insensitive)."""
    lower_map = {c.lower(): c for c in columns}
    for candidate in candidates:
        if candidate in lower_map:
            return lower_map[candidate]
    if required:
        raise ValueError(f"CSV must contain one of {list(candidates)}; got columns {list(columns)}")
    return None


def normalize_mode(value) -> str:
    """Map different representations of proxy mode to readable labels."""
    if isinstance(value, (int, float)):
        return "proxy" if value else "direct"
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"1", "true", "yes", "proxy", "with_proxy", "proxied", "socks"}:
            return "proxy"
        if v in {"0", "false", "no", "direct", "without_proxy", "none"}:
            return "direct"
        return value
    return str(value)


def load_data(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    cols_lower = [c.lower() for c in df.columns]

    buffer_col = pick_column(cols_lower, ["buffer_size_bytes", "buffer_bytes", "buffer_size", "buf_size", "buf"])
    file_col = pick_column(cols_lower, ["file_size_bytes", "file_bytes", "file_size"])

    throughput_col = pick_column(
        cols_lower, ["throughput_mbps", "bandwidth_mbps", "speed_mbps", "mbps"], required=False
    )
    if throughput_col is None:
        duration_col = pick_column(
            cols_lower, ["duration_seconds", "seconds", "time_seconds", "elapsed"], required=False
        )
        if duration_col is None:
            raise ValueError(
                "CSV missing throughput and duration columns. "
                "Add throughput_mbps (or duration_seconds + file size) to compute throughput."
            )
        df["throughput_mbps"] = df[file_col] * 8 / df[duration_col] / 1e6
    else:
        df["throughput_mbps"] = df[throughput_col]

    mode_col = pick_column(cols_lower, ["mode", "proxy", "with_proxy", "use_proxy"], required=False)
    if mode_col is None:
        df["mode"] = "all"
    else:
        df["mode"] = df[mode_col].apply(normalize_mode)

    df["buffer_kib"] = df[buffer_col] / 1024
    df["file_mib"] = df[file_col] / (1024 * 1024)

    grouped = (
        df.groupby(["file_mib", "buffer_kib", "mode"], as_index=False)["throughput_mbps"]
        .mean()
        .rename(columns={"throughput_mbps": "avg_throughput_mbps"})
    )
    return grouped


def plot_per_file(df: pd.DataFrame, out_dir: Path, log_x: bool) -> None:
    for file_size, subset in df.groupby("file_mib"):
        fig, ax = plt.subplots()
        for mode, mode_data in subset.groupby("mode"):
            sorted_data = mode_data.sort_values("buffer_kib")
            ax.plot(
                sorted_data["buffer_kib"],
                sorted_data["avg_throughput_mbps"],
                marker="o",
                label=mode,
            )

        ax.set_xlabel("Buffer size (KiB)")
        ax.set_ylabel("Throughput (Mbps)")
        ax.set_title(f"Throughput vs buffer (file size {int(file_size)} MiB)")
        if log_x:
            ax.set_xscale("log", base=2)
        ax.grid(True, which="both", linestyle="--", alpha=0.4)
        ax.legend(title="Mode")

        out_file = out_dir / f"buffer_vs_throughput_{int(file_size)}MiB.png"
        fig.tight_layout()
        fig.savefig(out_file, dpi=200)
        plt.close(fig)


def plot_average(df: pd.DataFrame, out_dir: Path, log_x: bool) -> None:
    averaged = (
        df.groupby(["buffer_kib", "mode"], as_index=False)["avg_throughput_mbps"]
        .mean()
        .rename(columns={"avg_throughput_mbps": "overall_throughput_mbps"})
    )

    fig, ax = plt.subplots()
    for mode, mode_data in averaged.groupby("mode"):
        sorted_data = mode_data.sort_values("buffer_kib")
        ax.plot(
            sorted_data["buffer_kib"],
            sorted_data["overall_throughput_mbps"],
            marker="o",
            label=mode,
        )

    ax.set_xlabel("Buffer size (KiB)")
    ax.set_ylabel("Average throughput across files (Mbps)")
    ax.set_title("Average throughput vs buffer size")
    if log_x:
        ax.set_xscale("log", base=2)
    ax.grid(True, which="both", linestyle="--", alpha=0.4)
    ax.legend(title="Mode")

    out_file = out_dir / "buffer_vs_throughput_average.png"
    fig.tight_layout()
    fig.savefig(out_file, dpi=200)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot buffer-size benchmark results.")
    parser.add_argument("csv_path", type=Path, help="CSV file produced by the benchmark script.")
    parser.add_argument("--out", type=Path, default=Path("plots"), help="Output directory for PNGs.")
    parser.add_argument("--linear-x", action="store_true", help="Use linear x-axis instead of log2.")
    parser.add_argument("--show", action="store_true", help="Display plots interactively (in addition to saving).")
    args = parser.parse_args()

    df = load_data(args.csv_path)
    args.out.mkdir(parents=True, exist_ok=True)

    log_x = not args.linear_x
    plot_per_file(df, args.out, log_x=log_x)
    plot_average(df, args.out, log_x=log_x)

    if args.show:
        plt.show()

    print(f"Wrote plots to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
