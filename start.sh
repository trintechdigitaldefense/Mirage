#!/usr/bin/env bash
# Mirage — TrinTech Digital Defense
# start.sh wires pull/upgrade, install, deploy, and day-to-day ops.
#
# ONE COMMAND (from your container, inside or parent of the clone):
#   curl -fsSL https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main/start.sh | bash -s -- upgrade
#
# Or from the repo directory:
#   bash start.sh upgrade
#   bash start.sh deploy
#   bash start.sh menu

set -euo pipefail

REPO_URL="https://github.com/trintechdigitaldefense/Mirage.git"
REPO_RAW="https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main"
BRANCH="main"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

# Resolve install root: prefer git root, else script dir, else ~/mirage
resolve_root() {
  if [[ -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/mirage/cli.py" ]]; then
    echo "${SCRIPT_DIR}"
    return
  fi
  if [[ -n "${SCRIPT_DIR}" && -d "${SCRIPT_DIR}/.git" ]]; then
    echo "${SCRIPT_DIR}"
    return
  fi
  if [[ -d "${HOME}/mirage/mirage" ]]; then
    echo "${HOME}/mirage"
    return
  fi
  if [[ -d "./mirage" && -f "./mirage/cli.py" ]]; then
    pwd
    return
  fi
  echo "${HOME}/mirage"
}

ROOT="$(resolve_root)"
CMD="${1:-menu}"
shift || true

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

ensure_repo() {
  need_cmd git
  need_cmd python3
  need_cmd pip3 || need_cmd pip

  if [[ ! -d "${ROOT}/.git" ]]; then
    log "Cloning Mirage into ${ROOT}..."
    mkdir -p "$(dirname "${ROOT}")"
    if [[ -d "${ROOT}" ]] && [[ -n "$(ls -A "${ROOT}" 2>/dev/null || true)" ]]; then
      warn "${ROOT} exists but is not a git repo — cloning into ${ROOT}.git-new then swapping"
      git clone --branch "${BRANCH}" "${REPO_URL}" "${ROOT}.git-new"
      # Prefer not to destroy user data; only swap if empty-ish
      if [[ ! -f "${ROOT}/mirage/cli.py" ]]; then
        rm -rf "${ROOT}"
        mv "${ROOT}.git-new" "${ROOT}"
      else
        warn "Keeping existing tree; pull manually if needed"
        rm -rf "${ROOT}.git-new"
      fi
    else
      git clone --branch "${BRANCH}" "${REPO_URL}" "${ROOT}"
    fi
  fi
  cd "${ROOT}"
}

cmd_upgrade() {
  ensure_repo
  cd "${ROOT}"
  log "Pulling latest ${BRANCH} from GitHub..."
  git fetch origin "${BRANCH}"
  git reset --hard "origin/${BRANCH}"
  ok "Code at $(git rev-parse --short HEAD)"

  log "Installing dependencies + editable package..."
  python3 -m pip install --upgrade pip -q 2>/dev/null || true
  python3 -m pip install -r requirements.txt -q
  python3 -m pip uninstall -y mirage >/dev/null 2>&1 || true
  python3 -m pip install -e . -q

  VER="$(python3 -c 'import mirage; print(mirage.__version__)' 2>/dev/null || echo unknown)"
  ok "Mirage ${VER} installed"
  python3 -c 'from mirage.cli import main; print("cli OK")' >/dev/null
  ok "CLI wired"

  echo
  mirage --version 2>/dev/null || python3 -m mirage --version 2>/dev/null || true
  echo
  ok "Upgrade complete. Next: bash start.sh deploy   (or  mirage checklist)"
}

cmd_install() {
  ensure_repo
  cd "${ROOT}"
  log "Installing deps (no git reset)..."
  python3 -m pip install -r requirements.txt -q
  python3 -m pip install -e . -q
  ok "Install done — $(python3 -c 'import mirage; print(mirage.__version__)')"
}

cmd_init() {
  need_cmd mirage || { err "Run: bash start.sh upgrade"; exit 1; }
  local org="${ORG:-${2:-Client}}"
  local roe="${ROE:-${3:-ROE-PENDING}}"
  local sector="${SECTOR:-${4:-general}}"
  log "Init org=${org} roe=${roe} sector=${sector}"
  mirage init --org "${org}" --auth-ref "${roe}" --sector "${sector}"
}

cmd_deploy() {
  need_cmd mirage || { err "Run: bash start.sh upgrade"; exit 1; }
  if [[ ! -f "${HOME}/.mirage/config.json" ]]; then
    warn "No config yet — run: bash start.sh init"
    warn "Or: mirage init --org NAME --auth-ref ROE-XXXX --sector clinic"
  fi
  log "Deploying full Mirage stack (Ctrl+C to stop)..."
  exec mirage deploy "${@:-}"
}

cmd_status() {
  need_cmd mirage || { err "Run: bash start.sh upgrade"; exit 1; }
  mirage status
  echo
  mirage health 2>/dev/null || true
}

cmd_probe() {
  log "Live probe against local decoys..."
  curl -s -m 3 "http://127.0.0.1:8080/" >/dev/null && ok "HTTP :8080" || warn "HTTP :8080 not responding (is deploy running?)"
  curl -s -m 3 "http://127.0.0.1:9000/" >/dev/null && ok "Cloud :9000" || warn "Cloud :9000 not responding"
  mirage alerts -r 5 2>/dev/null || true
}

cmd_report() {
  need_cmd mirage || exit 1
  mirage report --story "$@"
}

cmd_checklist() {
  need_cmd mirage || exit 1
  mirage checklist
}

cmd_menu() {
  cat <<EOF

  Mirage · TrinTech Digital Defense
  Root: ${ROOT}

  Usage:  bash start.sh <command>

  upgrade     git pull + reinstall (ONE command to update the tool)
  install     pip install only (no hard reset)
  init        mirage init (ORG= ROE= SECTOR= env or args)
  deploy      full stack: services, jail, canaries, SMB, beacons, cloud
  status      status + health
  probe       curl HTTP + cloud decoys, show recent alerts
  report      story report
  checklist   pilot checklist
  menu        this help

  One-liner from any container (fresh or existing):
    curl -fsSL ${REPO_RAW}/start.sh | bash -s -- upgrade

  Then:
    cd ~/mirage   # or your clone path
    bash start.sh init
    bash start.sh deploy

EOF
}

case "${CMD}" in
  upgrade|update|pull) cmd_upgrade "$@" ;;
  install)             cmd_install "$@" ;;
  init)                cmd_init "$@" ;;
  deploy)              cmd_deploy "$@" ;;
  status|health)       cmd_status "$@" ;;
  probe|test)          cmd_probe "$@" ;;
  report|story)        cmd_report "$@" ;;
  checklist)           cmd_checklist "$@" ;;
  menu|help|-h|--help) cmd_menu ;;
  *)
    err "Unknown command: ${CMD}"
    cmd_menu
    exit 1
    ;;
esac
