#!/usr/bin/env bash
# Запуск N узлов Void Connect на одной машине — для ручной проверки.
#
#   scripts/nodes.sh [N] [--fresh] [--release] [--root=DIR] [--base=PORT]
#
#   N            сколько узлов (по умолчанию 3, максимум 12)
#   --fresh      стереть данные узлов и начать с чистыми ключами
#   --release    release-сборка (марка работы в личке ~0,7 с вместо ~2–3 с)
#   --root=DIR   где лежат данные узлов (по умолчанию /tmp/void-nodes)
#   --base=PORT  порт первого узла (по умолчанию 7700; шаг между узлами — 10)
#
# Узлы работают в режиме --local: находят друг друга через /tmp/void-connect.
# У каждого своя папка данных — свой ключ, своя БД, свои настройки; без --fresh
# узлы сохраняют личность между запусками (удобно проверять поручительства).
# Логи — <root>/<имя>.log. Ctrl+C останавливает все узлы.
#
# Сценарии проверки — scripts/CHECKLIST.md.

set -euo pipefail

cd "$(dirname "$0")/.."

# Без nix-shell нет компилятора C и библиотек GL/X11 — перезапускаемся внутри.
if [[ -z "${IN_NIX_SHELL:-}" ]]; then
    exec nix-shell --run "$(printf '%q ' "$0" "$@")"
fi

count=3
fresh=0
profile=debug
root=/tmp/void-nodes
base=7700
for arg in "$@"; do
    case "$arg" in
        --fresh)    fresh=1 ;;
        --release)  profile=release ;;
        --root=*)   root="${arg#--root=}" ;;
        --base=*)   base="${arg#--base=}" ;;
        -h|--help)  sed -n '2,17p' "$0"; exit 0 ;;
        ''|*[!0-9]*) echo "Неизвестный аргумент: $arg (см. --help)" >&2; exit 1 ;;
        *)          count="$arg" ;;
    esac
done
if (( count < 1 || count > 12 )); then
    echo "Число узлов — от 1 до 12" >&2
    exit 1
fi

names=(Alice Bob Carol Dave Eve Frank Grace Heidi Ivan Judy Mallory Oscar)

echo "→ Сборка ($profile)…"
if [[ $profile == release ]]; then
    cargo build --release -p void-ui
else
    cargo build -p void-ui
fi
bin="target/$profile/void-connect"

if (( fresh )); then
    echo "→ Стираю данные узлов в $root"
    rm -rf "$root"
fi
mkdir -p "$root"

pids=()
stop() {
    trap - INT TERM EXIT
    echo
    echo "→ Останавливаю узлы…"
    kill "${pids[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap stop INT TERM EXIT

# Заголовок — без printf: он считает ширину в байтах, а кириллица — 2 байта на букву.
echo
echo "Узел     Порт   Сайты (HTTP)             Данные"
for (( i = 0; i < count; i++ )); do
    name="${names[$i]}"
    port=$(( base + 10 * i ))
    dir="$root/$name"
    mkdir -p "$dir"
    # Запись локального обнаружения от прошлого запуска на этом порту устарела.
    rm -f "/tmp/void-connect/$port.json"
    "$bin" "$name" "$port" --local --data-dir="$dir" >"$root/$name.log" 2>&1 &
    pids+=($!)
    printf '%-8s %-6s %-24s %s\n' "$name" "$port" "http://127.0.0.1:$(( port + 4 ))/" "$dir"
    sleep 0.3 # окна не наползают друг на друга при старте
done

echo
echo "Логи: $root/<имя>.log   (tail -f $root/*.log)"
echo "Ctrl+C — остановить все узлы."

# Ждём, пока закроются все окна (или Ctrl+C).
wait
