#!/bin/bash
# revkit Gateway 관리 스크립트
# 사용법: ./gateway.sh {start|stop|restart|status|log}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$HOME/.revkit/config.json"
LOG="/tmp/revkit-gateway.log"
PID_FILE="/tmp/revkit-gateway.pid"

REAL_IP=$(ip addr show 2>/dev/null | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | head -1)
GW_PORT=$(python3 -c "import json; print(json.load(open('$CONFIG')).get('gateway',{}).get('port',8080))" 2>/dev/null || echo 8080)
GW_URL="http://${REAL_IP}:${GW_PORT}"

start() {
    if pgrep -f "revkit.tools.gateway.daemon" > /dev/null 2>&1; then
        echo "[*] Gateway already running (PID $(pgrep -f 'revkit.tools.gateway.daemon'))"
        echo "    $GW_URL"
        return 0
    fi

    echo "[*] Starting Gateway..."
    nohup python3 -m revkit.tools.gateway.daemon --config "$CONFIG" >> "$LOG" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 3

    if curl -s --max-time 5 "$GW_URL/api/v1/health" | grep -q '"ok"'; then
        echo "[+] Gateway started: $GW_URL (PID $!)"
    else
        echo "[-] Gateway failed to start. Check log: $LOG"
        tail -5 "$LOG"
        return 1
    fi
}

stop() {
    if ! pgrep -f "revkit.tools.gateway.daemon" > /dev/null 2>&1; then
        echo "[*] Gateway not running"
        return 0
    fi

    echo "[*] Stopping Gateway..."
    pkill -f "revkit.tools.gateway.daemon"
    sleep 2

    if pgrep -f "revkit.tools.gateway.daemon" > /dev/null 2>&1; then
        echo "[*] Force killing..."
        pkill -9 -f "revkit.tools.gateway.daemon"
        sleep 1
    fi

    rm -f "$PID_FILE"
    echo "[+] Gateway stopped"
}

status() {
    if pgrep -f "revkit.tools.gateway.daemon" > /dev/null 2>&1; then
        PID=$(pgrep -f "revkit.tools.gateway.daemon")
        echo "[+] Gateway running (PID $PID)"
        echo "    URL: $GW_URL"
        HEALTH=$(curl -s --max-time 3 "$GW_URL/api/v1/health" 2>/dev/null)
        if [ -n "$HEALTH" ]; then
            echo "    Health: $HEALTH"
        else
            echo "    Health: unreachable"
        fi
        # 인스턴스 수
        revkit -R ida list 2>/dev/null | grep -c "|" | xargs -I{} echo "    IDA instances: {}"
        revkit -R jeb list 2>/dev/null | grep -c "|" | xargs -I{} echo "    JEB instances: {}"
    else
        echo "[-] Gateway not running"
    fi
}

log() {
    LINES=${2:-50}
    if [ -f "$LOG" ]; then
        tail -"$LINES" "$LOG"
    else
        echo "[-] Log file not found: $LOG"
    fi
}

case "${1:-status}" in
    start)   start ;;
    stop)    stop ;;
    restart) stop && sleep 1 && start ;;
    status)  status ;;
    log)     log "$@" ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|log [lines]}"
        echo ""
        echo "  start    Start Gateway daemon"
        echo "  stop     Stop Gateway daemon"
        echo "  restart  Restart Gateway daemon"
        echo "  status   Show Gateway status"
        echo "  log [N]  Show last N lines of log (default: 50)"
        ;;
esac
