#!/bin/bash
# =============================================================================
# SOCKSv5 Proxy Management Client
# =============================================================================
# A simple CLI client for the management protocol
#
# Usage:
#   ./mgmt_client.sh [command] [args...]
#   ./mgmt_client.sh              # Interactive mode
#   ./mgmt_client.sh stats        # Single command
#   ./mgmt_client.sh add user:pass
# =============================================================================

HOST="${MGMT_HOST:-127.0.0.1}"
PORT="${MGMT_PORT:-8080}"
TIMEOUT=2

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

send_command() {
    local cmd="$1"
    echo "$cmd" | nc -u -w $TIMEOUT "$HOST" "$PORT" 2>/dev/null
}

interactive_mode() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} SOCKSv5 Management Client${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "Connected to ${GREEN}$HOST:$PORT${NC}"
    echo -e "Type ${YELLOW}help${NC} for commands, ${YELLOW}quit${NC} to exit"
    echo ""
    
    while true; do
        echo -ne "${GREEN}mgmt>${NC} "
        read -r cmd
        
        # Handle local commands
        case "${cmd,,}" in
            quit|exit|q)
                echo "Goodbye!"
                break
                ;;
            "")
                continue
                ;;
            *)
                response=$(send_command "$cmd")
                if [ -n "$response" ]; then
                    echo "$response"
                else
                    echo -e "${RED}No response (server might be down)${NC}"
                fi
                ;;
        esac
    done
}

# Check if nc (netcat) is available
if ! command -v nc &> /dev/null; then
    echo "Error: netcat (nc) is required but not installed."
    echo "Install with: apt install netcat"
    exit 1
fi

# Parse command line
if [ $# -eq 0 ]; then
    # Interactive mode
    interactive_mode
else
    # Single command mode
    cmd="$*"
    response=$(send_command "$cmd")
    if [ -n "$response" ]; then
        echo "$response"
    else
        echo "No response from server"
        exit 1
    fi
fi
