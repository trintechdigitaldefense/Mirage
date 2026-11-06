#!/usr/bin/env bash
# Mirage — TrinTech Digital Defense
# Safe upgrade: never destroy local work or ~/.mirage data without explicit FORCE=1
#
#   curl -fsSL https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main/start.sh | bash -s -- upgrade
#   FORCE=1 bash start.sh upgrade   # allow git reset --hard when dirty

set -euo pipefail

REPO_URL="https://github.com/trintechdigitaldefense/Mirage.git"
REPO_RAW="https://raw.githubusercontent.com/trintechdigitaldefense/Mirage/main"
BRANCH="main"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

resolve_root() {
  if [[ -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/mirage/cli.py" ]]; then echo "${SCRIPT_DIR}"; return; fi
  if [[ -n "${SCRIPT_DIR}" && -d "${SCRIPT_DIR}/.git" ]]; then echo "${SCRIPT_DIR}"; return; fi
  if [[ -d "${HOME}/mirage/mirage" ]]; then echo "${HOME}/mirage"; return; fi
  if [[ -d "./mirage" && -f "./mirage/cli.py" ]]; then pwd; return; fi
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
  if [[ ! -d "${ROOT}/.git" ]]; then
    log "Cloning Mirage into ${ROOT}..."
    mkdir -p "$(dirname "${ROOT}")"
    if [[ -d "${ROOT}" ]] && [[ -n "$(ls -A "${ROOT}" 2>/dev/null || true)" ]]; then
      if [[ ! -f "${ROOT}/mirage/cli.py" ]]; then
        git clone --branch "${BRANCH}" "${REPO_URL}" "${ROOT}.git-new"
        rm -rf "${ROOT}"
        mv "${ROOT}.git-new" "${ROOT}"
      else
        warn "Keeping existing tree"
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

  # Never touch operator data
  ok "Preserving ~/.mirage (config, events, evidence) — never deleted by upgrade"

  if [[ -n "$(git status --porcelain 2>/dev/null || true)" ]]; then
    if [[ "${FORCE:-0}" != "1" ]]; then
      err "Working tree has local changes. Refusing destructive upgrade."
      err "Commit/stash them, or re-run with FORCE=1 bash start.sh upgrade"
      git status --short
      exit 1
    fi
    warn "FORCE=1 — backing up dirty tree tip before reset"
    git stash push -u -m "mirage-upgrade-stash-$(date +%Y%m%d%H%M%S)" || true
  fi

  log "Fetching ${BRANCH}..."
  git fetch origin "${BRANCH}"
  PREV="$(git rev-parse --short HEAD)"
  if [[ "${FORCE:-0}" == "1" ]]; then
    git reset --hard "origin/${BRANCH}"
  else
    if git merge-base --is-ancestor HEAD "origin/${BRANCH}" 2>/dev/null; then
      git merge --ff-only "origin/${BRANCH}" || git pull --ff-only origin "${BRANCH}"
    else
      warn "Non-fast-forward; using reset. Set FORCE=1 to allow if dirty."
      git reset --hard "origin/${BRANCH}"
    fi
  fi
  ok "Code ${PREV} → $(git rev-parse --short HEAD)"

  log "Installing into user environment (config untouched)..."
  python3 -m pip install --upgrade pip -q 2>/dev/null || true
  python3 -m pip install -r requirements.txt -q
  python3 -m pip install -e . -q

  VER="$(python3 -c 'import mirage; print(mirage.__version__)' 2>/dev/null || echo unknown)"
  ok "Mirage ${VER} installed"
  python3 -c 'from mirage.cli import main; from mirage.redaction import redact_details; print("cli+redaction OK")'
  ok "Upgrade complete. Deploy: bash start.sh deploy"
}

cmd_install() {
  ensure_repo
  cd "${ROOT}"
  python3 -m pip install -r requirements.txt -q
  python3 -m pip install -e . -q
  ok "Install done — $(python3 -c 'import mirage; print(mirage.__version__)')"
}

cmd_init() {
  need_cmd mirage || { err "Run: bash start.sh upgrade"; exit 1; }
  mirage init --org "${ORG:-${1:-Client}}" --auth-ref "${ROE:-${2:-ROE-PENDING}}" --sector "${SECTOR:-${3:-general}}"
}

cmd_deploy() {
  need_cmd mirage || { err "Run: bash start.sh upgrade"; exit 1; }
  if [[ $# -gt 0 ]]; then exec mirage deploy "$@"; else exec mirage deploy; fi
}

cmd_status() { need_cmd mirage; mirage status; mirage health 2>/dev/null || true; }
cmd_probe() {
  curl -s -m 3 "http://127.0.0.1:8080/" >/dev/null && ok "HTTP :8080" || warn "HTTP :8080 down"
  curl -s -m 3 "http://127.0.0.1:8081/.env" >/dev/null && ok "WebAPI :8081" || warn "WebAPI down"
  mirage alerts -r 5 2>/dev/null || true
}
cmd_report() { need_cmd mirage; mirage report --story; }
cmd_checklist() { need_cmd mirage; mirage checklist; }

cmd_menu() {
  cat <<EOF

  Mirage · TrinTech Digital Defense
  Root: ${ROOT}

  upgrade     safe pull + reinstall (FORCE=1 if dirty tree)
  install     pip only
  init / deploy / status / probe / report / checklist

  Data dir ~/.mirage is NEVER deleted by upgrade.

EOF
}

case "${CMD}" in
  upgrade|update|pull) cmd_upgrade ;;
  install) cmd_install ;;
  init) cmd_init "$@" ;;
  deploy) cmd_deploy "$@" ;;
  status|health) cmd_status ;;
  probe|test) cmd_probe ;;
  report|story) cmd_report ;;
  checklist) cmd_checklist ;;
  menu|help|-h|--help) cmd_menu ;;
  *) err "Unknown: ${CMD}"; cmd_menu; exit 1 ;;
esac
