#!/usr/bin/env bash
# ===========================================================================
#  backscrape — Cloudflare origin hunter (probability edition)
#  Author: Omar Emad
#
#  backscrape [--domain X] [--threads N] [--quick] [--no-brute]
#             [--pause] [--reconfigure-apis]
#
#  FOR AUTHORIZED SECURITY TESTING ONLY — see DISCLAIMER.md
# ===========================================================================
set -uo pipefail
[ -r /dev/tty ] && exec </dev/tty

VERSION=8.0
AUTHOR="Omar Emad"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

C_R=$'\e[0m'; C_B=$'\e[1m'; C_DIM=$'\e[2m'
C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
C_BLU=$'\e[34m'; C_MAG=$'\e[35m'; C_CYN=$'\e[36m'

CONF_DIR="$HOME/.config/backscrape"
CONF="$CONF_DIR/keys.conf"
CF_RANGES="$CONF_DIR/cf-v4.txt"
RESOLVERS="$CONF_DIR/resolvers.txt"
RESULTS="$HOME/backscrape-results"
LOG="/dev/null"

load_provider_config() {
  [ -f "$CONF" ] || return 0
  while IFS='=' read -r name value; do
    case "$name" in
      SHODAN_KEY_B64|CENSYS_TOKEN_B64|VT_KEY_B64|ST_KEY_B64)
        decoded="$(printf '%s' "$value" | base64 -d 2>/dev/null)" || continue
        case "$name" in
          SHODAN_KEY_B64) SHODAN_KEY="${SHODAN_KEY:-$decoded}" ;;
          CENSYS_TOKEN_B64) CENSYS_TOKEN="${CENSYS_TOKEN:-$decoded}" ;;
          VT_KEY_B64) VT_KEY="${VT_KEY:-$decoded}" ;;
          ST_KEY_B64) ST_KEY="${ST_KEY:-$decoded}" ;;
        esac
        unset decoded ;;
      PROVIDERS_CONFIGURED) [ "$value" = "1" ] && PROVIDERS_CONFIGURED=1 ;;
    esac
  done < "$CONF"
}
load_provider_config
SHODAN_KEY="${SHODAN_KEY:-${SHODAN_API_KEY:-}}"
CENSYS_TOKEN="${CENSYS_TOKEN:-${CENSYS_PAT:-}}"
VT_KEY="${VT_KEY:-${VT_API_KEY:-}}"
ST_KEY="${ST_KEY:-${SECURITYTRAILS_KEY:-}}"

DOMAIN=""; OUTDIR=""; THREADS=30; BRUTE=1; PAUSE=0; QUICK=0; WILD_IP=""
PHASE_NAME=""; PHASE_START=$SECONDS; SCAN_START=$SECONDS
trap 'printf "\n%s  interrupted%s\n" "$C_RED" "$C_R"; jobs -p | xargs -r kill 2>/dev/null; [ "$PAUSE" = 1 ] && { printf "  press enter"; read -r _; }; exit 130' INT TERM

err() {
  local code="$1" what="$2" why="$3" fix="$4"
  printf '\n%s┌─ %s%s\n' "$C_RED$C_B" "$code" "$C_R"
  printf '%s│%s %s\n' "$C_RED" "$C_R" "$what"
  printf '%s│%s %s%s%s\n' "$C_RED" "$C_R" "$C_DIM" "$why" "$C_R"
  printf '%s│%s %s→ %s%s\n' "$C_RED" "$C_R" "$C_YEL" "$fix" "$C_R"
  printf '%s└─%s\n' "$C_RED" "$C_R"
  [ "${LOG:-/dev/null}" != /dev/null ] && printf '[ERR] %s | %s | %s\n' "$code" "$what" "$why" >> "$LOG" 2>/dev/null
  return 0
}
log()   { printf '%s[·]%s %s\n' "$C_BLU" "$C_R" "$*"; [ "${LOG:-/dev/null}" != /dev/null ] && printf '[..] %s\n' "$*" >> "$LOG" 2>/dev/null; return 0; }
ok()    { printf '%s[+]%s %s\n' "$C_GRN" "$C_R" "$*"; [ "${LOG:-/dev/null}" != /dev/null ] && printf '[OK] %s\n' "$*" >> "$LOG" 2>/dev/null; return 0; }
warn()  { printf '%s[!]%s %s\n' "$C_YEL" "$C_R" "$*"; [ "${LOG:-/dev/null}" != /dev/null ] && printf '[!!] %s\n' "$*" >> "$LOG" 2>/dev/null; return 0; }
hr()    { printf '%s%s%s\n' "$C_DIM" "──────────────────────────────────────────────────────────────────────" "$C_R"; }
phase() {
  if [ -n "$PHASE_NAME" ]; then printf '%s  ⏱ %ss%s\n' "$C_DIM" "$((SECONDS - PHASE_START))" "$C_R"; fi
  PHASE_NAME="$*"; PHASE_START=$SECONDS
  printf '\n%s▌ %s%s\n' "$C_B$C_MAG" "$*" "$C_R"; hr
}
die()  { err "$1" "$2" "$3" "$4"; [ "$PAUSE" = 1 ] && { printf "\n  press enter"; read -r _; }; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
sudo_() { sudo "$@" </dev/tty; }

detect_pkg() {
  if have pacman; then echo arch
  elif have apt-get; then echo debian
  elif have dnf; then echo fedora
  elif have zypper; then echo suse
  elif have apk; then echo alpine
  else echo unknown; fi
}

ip_in_cidr() {
  printf '%s %s\n' "$1" "$2" | awk '
    function ip2n(s, a) { split(s, a, "."); return a[1]*16777216 + a[2]*65536 + a[3]*256 + a[4] }
    {
      n = split($2, p, "/")
      base = ip2n(p[1]); bits = (n > 1) ? p[2] + 0 : 32
      ip = ip2n($1); shift = 32 - bits
      if (shift >= 32) { print 1; exit }
      print (int(ip / 2^shift) == int(base / 2^shift)) ? 1 : 0
      exit
    }' 2>/dev/null
}
cf_has() {
  local ip="$1" line
  [ -s "$CF_RANGES" ] || return 1
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    [ "$(ip_in_cidr "$ip" "$line")" = "1" ] && return 0
  done < "$CF_RANGES"
  return 1
}

pscale() {
  local p="$1" filled empty i bar=""
  p="${p:-0}"; [ "$p" -gt 100 ] 2>/dev/null && p=100; [ "$p" -lt 0 ] 2>/dev/null && p=0
  filled=$((p / 10)); empty=$((10 - filled))
  for ((i = 0; i < filled; i++)); do bar+="█"; done
  for ((i = 0; i < empty; i++)); do bar+="░"; done
  printf '[%s] %s%%' "$bar" "$p"
}
p_label() {
  local p="$1"
  if   [ "$p" -ge 80 ]; then printf '%sVERY HIGH — confirmed origin%s' "$C_GRN$C_B" "$C_R"
  elif [ "$p" -ge 70 ]; then printf '%sHIGH — possible origin%s' "$C_YEL$C_B" "$C_R"
  elif [ "$p" -ge 50 ]; then printf '%sMODERATE — likely origin%s' "$C_YEL$C_B" "$C_R"
  elif [ "$p" -ge 30 ]; then printf '%sLOW — weak signal%s' "$C_YEL" "$C_R"
  else                       printf '%sVERY LOW — probably not the origin%s' "$C_DIM" "$C_R"
  fi
}

validate_shodan() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://api.shodan.io/api-info?key=$1" 2>/dev/null)"
  [ "$code" = "200" ]
}
validate_censys() {
  local b code
  b="$(printf '%s' "$1" | tr -d '\n' | base64 | tr -d '\n')"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "Authorization: Basic $b" \
          "https://search.censys.io/api/v1/account" 2>/dev/null)"
  [ "$code" = "200" ]
}
validate_vt() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "x-apikey: $1" \
          "https://www.virustotal.com/api/v3/users/current" 2>/dev/null)"
  [ "$code" = "200" ]
}
validate_st() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "APIKEY: $1" \
          "https://api.securitytrails.com/v1/ping" 2>/dev/null)"
  [ "$code" = "200" ]
}

ask_key() {
  local label="$1" var="$2" hint="$3" validator="$4"
  local current="${!var:-}" entered="" tries=0 answer=""
  while :; do
    printf '\n  %s%s%s %s%s%s\n' "$C_B$C_CYN" "$label" "$C_R" "$C_DIM" "$hint" "$C_R" >&2
    if [ -n "$current" ]; then
      printf '  %svalue currently set — press enter to keep it%s\n' "$C_DIM" "$C_R" >&2
    else
      printf '  %spress enter to skip%s\n' "$C_DIM" "$C_R" >&2
    fi
    printf '  %s> %s' "$C_CYN" "$C_R" >&2
    entered=""; read -r -s entered || entered=""
    printf '\n' >&2
    if [ -z "$entered" ]; then printf '%s' "$current"; return 0; fi
    printf '  %schecking key…%s' "$C_DIM" "$C_R" >&2
    if "$validator" "$entered"; then
      printf '\r  %s[+] key valid%s      \n' "$C_GRN" "$C_R" >&2
      printf '%s' "$entered"; return 0
    fi
    printf '\r  %s[!] key rejected by API%s\n' "$C_YEL" "$C_R" >&2
    tries=$((tries + 1))
    if [ "$tries" -ge 3 ]; then
      printf '  %skeep it anyway? [y/N] %s' "$C_DIM" "$C_R" >&2
      read -r answer || answer=""
      case "${answer,,}" in
        y|yes) printf '%s' "$entered"; return 0 ;;
        *) printf '%s' "$current"; return 0 ;;
      esac
    fi
  done
}

provider_setup() {
  mkdir -p "$CONF_DIR" 2>/dev/null || { err ERR_CONFIG "Cannot create config dir" "Permission denied." "check ~/.config permissions"; return 1; }
  chmod 700 "$CONF_DIR" 2>/dev/null || true

  local first_run=0
  [ "${RECONFIGURE_APIS:-0}" = 1 ] && first_run=1
  [ "${PROVIDERS_CONFIGURED:-0}" = 1 ] || first_run=1
  if [ "$first_run" = 0 ]; then
    if [ -z "${SHODAN_KEY:-}" ] && [ -z "${CENSYS_TOKEN:-}" ] && [ -z "${VT_KEY:-}" ]; then first_run=1; fi
  fi

  if [ "$first_run" = 0 ]; then
    ok "saved provider configuration loaded"
    if [ -n "${SHODAN_KEY:-}" ]; then
      if validate_shodan "$SHODAN_KEY"; then ok "Shodan: configured (key valid)"
      else warn "Shodan: saved key FAILED validation — run: backscrape --reconfigure-apis"; fi
    else warn "Shodan: not configured"; fi
    if [ -n "${CENSYS_TOKEN:-}" ]; then
      if validate_censys "$CENSYS_TOKEN"; then ok "Censys: configured (key valid)"
      else warn "Censys: saved key FAILED validation — must be API_ID:SECRET; run: backscrape --reconfigure-apis"; fi
    else warn "Censys: not configured"; fi
    if [ -n "${VT_KEY:-}" ]; then
      if validate_vt "$VT_KEY"; then ok "VirusTotal: configured (key valid)"
      else warn "VirusTotal: saved key FAILED validation — run: backscrape --reconfigure-apis"; fi
    else warn "VirusTotal: not configured"; fi
    [ -n "${ST_KEY:-}" ] && ok "SecurityTrails: configured" || log "SecurityTrails: not configured (optional)"
    return 0
  fi

  phase "API keys — first run setup"
  printf '  %sShodan, Censys and VirusTotal unlock the API phases.\n' "$C_DIM"
  printf '  Keys are stored base64-encoded in %s (chmod 600).%s\n' "$CONF" "$C_R"

  local shodan="" censys="" vt="" st=""
  shodan="$(ask_key "Shodan API key" SHODAN_KEY "https://account.shodan.io/" validate_shodan)"
  censys="$(ask_key "Censys API credentials" CENSYS_TOKEN "API_ID:SECRET from https://search.censys.io/account/api" validate_censys)"
  vt="$(ask_key "VirusTotal API key" VT_KEY "https://www.virustotal.com/gui/my-apikey" validate_vt)"
  printf '\n  %sSecurityTrails is optional (historical DNS).%s\n' "$C_DIM" "$C_R"
  st="$(ask_key "SecurityTrails API key (optional)" ST_KEY "https://securitytrails.com/app/account/credentials" validate_st)"

  SHODAN_KEY="$shodan"; CENSYS_TOKEN="$censys"; VT_KEY="$vt"; ST_KEY="$st"

  local tmp="${CONF}.tmp.$$" saved=0
  umask 077
  { printf '# backscrape credential data; base64-encoded, not executable shell\n'; } > "$tmp" || return 1
  if [ -n "$SHODAN_KEY" ];   then printf 'SHODAN_KEY_B64=%s\n'   "$(printf '%s' "$SHODAN_KEY"   | base64 | tr -d '\n')" >> "$tmp"; saved=$((saved + 1)); fi
  if [ -n "$CENSYS_TOKEN" ]; then printf 'CENSYS_TOKEN_B64=%s\n' "$(printf '%s' "$CENSYS_TOKEN" | base64 | tr -d '\n')" >> "$tmp"; saved=$((saved + 1)); fi
  if [ -n "$VT_KEY" ];       then printf 'VT_KEY_B64=%s\n'       "$(printf '%s' "$VT_KEY"       | base64 | tr -d '\n')" >> "$tmp"; saved=$((saved + 1)); fi
  if [ -n "$ST_KEY" ];       then printf 'ST_KEY_B64=%s\n'       "$(printf '%s' "$ST_KEY"       | base64 | tr -d '\n')" >> "$tmp"; saved=$((saved + 1)); fi
  if [ "$saved" -gt 0 ]; then printf 'PROVIDERS_CONFIGURED=1\n' >> "$tmp"; PROVIDERS_CONFIGURED=1; else PROVIDERS_CONFIGURED=0; fi
  chmod 600 "$tmp"
  mv -f "$tmp" "$CONF" || { rm -f "$tmp"; err ERR_CONFIG "Could not save config" "Unable to replace $CONF." "check disk space and permissions"; return 1; }
  chmod 600 "$CONF"
  if [ "$saved" -eq 0 ]; then warn "no keys saved — you will be asked again on the next run"
  else ok "$saved key(s) saved to $CONF"; fi
  return 0
}

banner() {
  clear 2>/dev/null || true
  if have figlet; then
    figlet -f standard "backscrape" | while IFS= read -r l; do printf '%s%s%s\n' "$C_CYN" "$l" "$C_R"; done
  else
    printf '%s  b a c k s c r a p e%s\n' "$C_CYN" "$C_R"
  fi
  printf '%s  v%s  ·  author: %s  ·  cloudflare origin hunter%s\n' "$C_MAG" "$VERSION" "$AUTHOR" "$C_R"
}

fetch() {
  local url="$1" out="$2" mt="${3:-60}" opt="${4:-0}" i rc=0 code=0
  mkdir -p "$(dirname "$out")" 2>/dev/null || true
  for i in 1 2 3; do
    code="$(curl -sSL --max-time "$mt" -A "$UA" "$url" -o "$out" -w '%{http_code}' 2>>"$LOG")"
    rc=$?
    if [ "$rc" = 0 ] && [ "$code" = "200" ] && [ -s "$out" ]; then return 0; fi
    if [ "$rc" = 0 ] && [ "$code" != "200" ] && [ "$code" != "000" ]; then
      [ "$opt" = "1" ] && log "source unavailable (HTTP $code): ${url%%\?*} — skipped" \
        || err ERR_NET "Could not fetch ${url%%\?*}" "server returned HTTP $code." "the source may be down or rate-limiting you"
      return 1
    fi
    [ "$rc" = 0 ] && warn "empty body from ${url%%\?*} (try $i/3)"
    sleep $((i * 3))
  done
  [ "$opt" = "1" ] && log "source unreachable (curl exit $rc): ${url%%\?*} — skipped" \
    || err ERR_NET "Could not fetch ${url%%\?*}" "3 failures, curl exit $rc." "check connectivity"
  return 1
}

accept_disclaimer() {
  [ -f "$CONF_DIR/.disclaimer-accepted" ] && return 0
  mkdir -p "$CONF_DIR" 2>/dev/null || true
  printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_YEL$C_B" "$C_R"
  printf '%s║%s  AUTHORIZED USE ONLY. By continuing you confirm that you%s\n' "$C_YEL$C_B" "$C_R" ""
  printf '%s║%s  own the target or have written permission to test it,%s\n' "$C_YEL$C_B" "$C_R" ""
  printf '%s║%s  and you accept FULL legal responsibility for its use.%s\n' "$C_YEL$C_B" "$C_R" ""
  printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$C_YEL$C_B" "$C_R"
  local d=""; printf '  %sI accept and take full responsibility [y/N]: %s' "$C_YEL" "$C_R"
  read -r d 2>/dev/null || true
  case "${d,,}" in
    y|yes) touch "$CONF_DIR/.disclaimer-accepted"; ok "disclaimer accepted" ;;
    *) printf '\n  %sexiting — only authorized use is permitted.%s\n' "$C_RED" "$C_R"; exit 1 ;;
  esac
}

bootstrap() {
  phase "bootstrap — downloading dependencies"
  local pkgmgr; pkgmgr="$(detect_pkg)"
  case "$pkgmgr" in
    arch) ok "distro: Arch (pacman)" ;; debian) ok "distro: Debian/Ubuntu (apt)" ;;
    fedora) ok "distro: Fedora/RHEL (dnf)" ;; suse) ok "distro: openSUSE (zypper)" ;;
    alpine) ok "distro: Alpine (apk)" ;; *) warn "unknown distro — best-effort mode" ;;
  esac

  local miss=() t pac=() goi=()
  for t in curl jq dig whois openssl python3 figlet subfinder dnsx httpx puredns assetfinder unfurl massdns; do
    have "$t" || miss+=("$t")
  done

  if [ "${#miss[@]}" -eq 0 ]; then ok "all tools present"
  else
    warn "installing ${#miss[@]} missing tool(s)"
    for t in "${miss[@]}"; do
      case "$t" in
        dig) case "$pkgmgr" in
               arch) pac+=(bind) ;; debian) pac+=(dnsutils) ;;
               fedora|suse) pac+=(bind-utils) ;; alpine) pac+=(bind-tools) ;;
             esac ;;
        whois) pac+=(whois) ;; openssl) pac+=(openssl) ;; jq) pac+=(jq) ;;
        curl) pac+=(curl) ;; figlet) pac+=(figlet) ;;
        massdns) case "$pkgmgr" in
                   arch|debian) pac+=(massdns) ;; *) goi+=(github.com/blechschmidt/massdns@latest) ;;
                 esac ;;
        subfinder) goi+=(github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest) ;;
        dnsx) goi+=(github.com/projectdiscovery/dnsx/cmd/dnsx@latest) ;;
        httpx) goi+=(github.com/projectdiscovery/httpx/cmd/httpx@latest) ;;
        puredns) goi+=(github.com/d3mondev/puredns/v2@latest) ;;
        assetfinder) goi+=(github.com/tomnomnom/assetfinder@latest) ;;
        unfurl) goi+=(github.com/tomnomnom/unfurl@latest) ;;
      esac
    done
    if [ "${#pac[@]}" -gt 0 ]; then
      printf '  %sneeds sudo for %s. continue? [Y/n] %s' "$C_DIM" "$pkgmgr" "$C_R"
      local a="y"; read -t 15 -r a 2>/dev/null || true
      case "${a:-y}" in
        [Nn]*) err ERR_DEP "Install skipped" "Core curl/dig path still works." "rerun and accept the prompt" ;;
        *)
          case "$pkgmgr" in
            arch)   sudo_ pacman -Sy --needed --noconfirm ${pac[@]+"${pac[@]}"} 2>>"$LOG" || err ERR_PERM "pacman failed" "sudo declined or DB locked." "sudo pacman -Syu --needed ${pac[*]}" ;;
            debian) { sudo_ apt-get update -qq 2>>"$LOG" || true; sudo_ apt-get install -y ${pac[@]+"${pac[@]}"} 2>>"$LOG"; } || err ERR_PERM "apt failed" "sudo declined or package missing." "sudo apt-get install -y ${pac[*]}" ;;
            fedora) sudo_ dnf install -y ${pac[@]+"${pac[@]}"} 2>>"$LOG" || err ERR_PERM "dnf failed" "sudo declined." "sudo dnf install -y ${pac[*]}" ;;
            suse)   sudo_ zypper --non-interactive install ${pac[@]+"${pac[@]}"} 2>>"$LOG" || err ERR_PERM "zypper failed" "sudo declined." "sudo zypper install ${pac[*]}" ;;
            alpine) sudo_ apk add ${pac[@]+"${pac[@]}"} 2>>"$LOG" || err ERR_PERM "apk failed" "sudo declined." "sudo apk add ${pac[*]}" ;;
          esac ;;
      esac
    fi
    if [ "${#goi[@]}" -gt 0 ] && ! have go; then
      case "$pkgmgr" in
        arch) sudo_ pacman -S --needed --noconfirm go 2>>"$LOG" || true ;;
        debian) sudo_ apt-get install -y golang-go 2>>"$LOG" || true ;;
        fedora) sudo_ dnf install -y golang 2>>"$LOG" || true ;;
        suse) sudo_ zypper --non-interactive install go 2>>"$LOG" || true ;;
        alpine) sudo_ apk add go 2>>"$LOG" || true ;;
      esac
    fi
    if [ "${#goi[@]}" -gt 0 ] && have go; then
      export PATH="$PATH:$HOME/go/bin"
      local p
      for p in ${goi[@]+"${goi[@]}"}; do
        log "go install ${p##*/}"
        GO111MODULE=on GOPATH="$HOME/go" timeout 600 go install -v "$p" 2>>"$LOG" >/dev/null || warn "go install failed: ${p##*/}"
      done
    fi
  fi
  export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"

  if ! python3 -c 'import mmh3' >/dev/null 2>&1; then
    log "installing mmh3 (favicon hashing)"
    if have pipx; then pipx install mmh3 2>>"$LOG" || true
    elif have pip3; then pip3 install --user --break-system-packages mmh3 2>>"$LOG" || pip3 install --user mmh3 2>>"$LOG" || warn "mmh3 install failed — favicon hunt disabled"
    fi
    python3 -c 'import mmh3' >/dev/null 2>&1 && ok "mmh3 installed"
  fi

  [ -d /usr/share/seclists ] || { log "fetching wordlists"; sudo_ git clone --depth 1 -q https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>>"$LOG" \
      || { mkdir -p "$CONF_DIR"; timeout 300 git clone --depth 1 -q https://github.com/danielmiessler/SecLists.git "$CONF_DIR/SecLists" 2>>"$LOG" || err ERR_NOWL "SecLists clone failed" "No network or disk space." "brute force will be skipped"; }; }
  [ -s "$RESOLVERS" ] || fetch "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" "$RESOLVERS" 30
  [ -s "$CF_RANGES" ] || { fetch "https://www.cloudflare.com/ips-v4/" "$CF_RANGES" 30 && ok "cloudflare ranges cached"; }

  provider_setup || warn "provider configuration could not be completed"
  mkdir -p "$RESULTS"
  ok "ready"
}

collect_to() {
  tr 'A-Z' 'a-z' | sed -e 's/^\*\.//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/,$//' \
    | awk -v d="$DOMAIN" 'NF && ($0==d || substr($0, length($0)-length(d)) == "." d)' > "$1"
}
asn_of() { timeout 15 whois -h whois.cymru.com " -v $1" 2>/dev/null | tail -n +2 | head -1; }
classify() {
  local line org
  line="$(asn_of "$1")"; [ -n "$line" ] || { echo "?"; return; }
  org="$(printf '%s' "$line" | awk -F'|' '{print $NF}' | sed 's/^ *//;s/ *$//')"
  [ -z "$org" ] && { echo "?"; return; }
  printf '%s' "$org" | grep -qiE 'cloudflare' && { echo "cloudflare"; return; }
  printf '%s' "$org" | grep -qiE 'akamai|fastly|cloudfront|amazon|imperva|incapsula|sucuri|stackpath|edgio|limelight|cdn77|keycdn|bunny|gcore|alibaba|tencent cloud' && { echo "cdn"; return; }
  printf '%s' "$org" | grep -qiE 'ovh|hetzner|digitalocean|vultr|linode|contabo|leaseweb|scaleway|oracle|microsoft|azure|google|aws|amazon' && { echo "hosting"; return; }
  echo "isp"
}
classify_cached() {
  local ip="$1" key line cls
  key="$(printf '%s' "$ip" | cut -d. -f1-3)"
  line="$(grep -m1 "^${key}|" asn_cache.txt 2>/dev/null)"
  if [ -n "$line" ]; then printf '%s' "${line#*|}"; return; fi
  cls="$(classify "$ip")"
  printf '%s|%s\n' "$key" "$cls" >> asn_cache.txt 2>/dev/null
  printf '%s' "$cls"
}

score_py() {
cat > score.py <<'PYEOF'
import sys, json, re, os, difflib, hashlib
a = dict(x.split('=', 1) for x in sys.argv[1:] if '=' in x)
def rd(p):
    try:
        if p and os.path.exists(p): return open(p, 'rb').read()[:300000].decode('utf-8', 'ignore')
    except Exception: pass
    return ''
def sha(p):
    try: return hashlib.sha256(open(p, 'rb').read()).hexdigest()
    except Exception: return ''
def norm(s):
    s = re.sub(r'(?is)<(script|style).*?</\1>', ' ', s)
    s = re.sub(r'(?s)<[^>]+>', ' ', s)
    return re.sub(r'\s+', ' ', s).strip().lower()
def cookies(h):
    out = set()
    for line in h.splitlines():
        m = re.match(r'(?i)set-cookie:\s*([^=;\s]+)', line)
        if m: out.add(m.group(1).lower())
    return out
code = a.get('code', '000')
score, ev = 0, []
base_html, cand_html = rd(a.get('base')), rd(a.get('cand'))
if code.startswith('2'): score += 2; ev.append('HTTP ' + code)
elif code.startswith('3'): score += 1; ev.append('HTTP ' + code)
ta = re.search(r'(?is)<title[^>]*>(.*?)</title>', base_html)
tb = re.search(r'(?is)<title[^>]*>(.*?)</title>', cand_html)
if ta and tb:
    x, y = ta.group(1).strip().lower(), tb.group(1).strip().lower()
    if x and x == y: score += 3; ev.append('title match')
    elif x and y and (x in y or y in x): score += 1; ev.append('title overlap')
na, nb = norm(base_html), norm(cand_html)
if na and nb:
    r = difflib.SequenceMatcher(None, na[:120000], nb[:120000]).quick_ratio()
    if r >= 0.90: score += 3; ev.append('body %.0f%%' % (r * 100))
    elif r >= 0.60: score += 2; ev.append('body %.0f%%' % (r * 100))
    elif r >= 0.30: score += 1; ev.append('body %.0f%%' % (r * 100))
srv = a.get('srv', '')
if srv and 'cloudflare' not in srv.lower(): score += 2; ev.append('server:' + srv)
if a.get('cert') == '1': score += 2; ev.append('cert SAN match')
if a.get('asn') == 'hosting': score += 1; ev.append('hosting ASN')
if a.get('ptr') == '1': score += 2; ev.append('PTR ' + a.get('ptrname', '')[:40])
sb, sc_ = sha(a.get('bfav')), sha(a.get('cfav'))
if sb and sc_ and sb == sc_: score += 3; ev.append('favicon match')
cb, cc = cookies(rd(a.get('bhead'))), cookies(rd(a.get('chead')))
if cb and cc and (cb & cc): score += 1; ev.append('cookie overlap')
blob = cand_html[:20000].lower()
if 'just a moment' in blob or 'cf-error' in blob or 'attention required' in blob:
    score -= 4; ev.append('cf challenge')
verdict = 'REAL' if score >= 8 else ('LIKELY' if score >= 5 else 'WEAK')
conf = max(0, min(99, score * 10))
print(json.dumps({'score': score, 'conf': conf, 'verdict': verdict, 'evidence': ev}))
PYEOF
}
cert_match() {
  local out
  out="$(timeout 12 openssl s_client -connect "$2:443" -servername "$1" </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -1)"
  printf '%s' "$out" | grep -qiF "$DOMAIN" && echo 1 || echo 0
}

verify_host() {
  local host="$1" ip="$2" tmp hdr fav code srv cert sc v ptrflag=0 ptrname="" cls port scheme pe
  [ -n "$WILD_IP" ] && [ "$ip" = "$WILD_IP" ] && return 0
  grep -qxF "$ip" dead_ips.txt 2>/dev/null && return 0
  if cf_has "$ip"; then cls="cloudflare"; else cls="$(classify_cached "$ip")"; fi
  case "$cls" in cloudflare|cdn) [ "$host" = "$DOMAIN" ] || return 0 ;; esac
  tmp="$(mktemp /tmp/bs.XXXXXX)"; hdr="$(mktemp /tmp/bsh.XXXXXX)"; fav="$(mktemp /tmp/bsf.XXXXXX)"
  code="000"
  for pe in "443:https" "80:http" "8443:https" "8080:http" "2053:https" "2083:https" "2087:https" "2096:https" "8880:http"; do
    port="${pe%%:*}"; scheme="${pe##*:}"
    code="$(curl -sk --max-time 8 -A "$UA" --resolve "$host:$port:$ip" -D "$hdr" -o "$tmp" -w '%{http_code}' "$scheme://$host/" 2>>"$LOG")"
    [ -n "$code" ] && [ "$code" != "000" ] && break
    code="000"
  done
  if [ "$code" = "000" ]; then
    printf '%-40s %-16s %-10s %-5s %-5s %-5s %-8s %s\n' "$host" "$ip" "$cls" "-" "-" "-" "DEAD" "no TCP answer" >> "$CAND"
    printf '%s\n' "$ip" >> dead_ips.txt
    rm -f "$tmp" "$hdr" "$fav"; return 0
  fi
  srv="$(grep -i '^server:' "$hdr" 2>/dev/null | head -1 | cut -d' ' -f2- | tr -d '\r')"
  cert="$(cert_match "$host" "$ip")"
  ptrname="$(timeout 5 dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')"
  [ -n "$ptrname" ] && printf '%s' "$ptrname" | grep -qiF "$DOMAIN" && ptrflag=1
  curl -sk --max-time 8 -A "$UA" --resolve "$host:443:$ip" -o "$fav" "https://$host/favicon.ico" 2>>"$LOG"
  sc="$(python3 "$PWD/score.py" "base=$BASE" "cand=$tmp" "code=$code" "srv=${srv:-}" \
        "cert=$cert" "asn=$cls" "ptr=$ptrflag" "ptrname=$ptrname" \
        "bfav=$BASEFAV" "cfav=$fav" "bhead=$BASEH" "chead=$hdr" 2>/dev/null)"
  [ -n "$sc" ] || sc='{"score":0,"conf":0,"verdict":"WEAK","evidence":["scorer error"]}'
  printf '%-40s %-16s %-10s %-5s %-5s %-5s %-8s %s\n' "$host" "$ip" "$cls" "$code" \
    "$(printf '%s' "$sc" | jq -r .score)" "$(printf '%s' "$sc" | jq -r .conf)" \
    "$(printf '%s' "$sc" | jq -r .verdict)" \
    "$(printf '%s' "$sc" | jq -r '.evidence|join(", ")')" >> "$CAND"
  v="$(printf '%s' "$sc" | jq -r .verdict)"
  [ "$v" = "REAL" ] && ok "$host -> $ip  probability $(printf '%s' "$sc" | jq -r .conf)%%"
  rm -f "$tmp" "$hdr" "$fav"
}
classify_one() {
  local host="$1" ip="$2" cls
  if cf_has "$ip"; then cls="cloudflare"; else cls="$(classify_cached "$ip")"; fi
  printf '%s %s %s\n' "$host" "$ip" "$cls"
}

run_scan() {
  local STAMP; STAMP="$(date +%Y%m%d-%H%M%S)"
  OUTDIR="$RESULTS/$DOMAIN-$STAMP"
  mkdir -p "$OUTDIR" || die ERR_PERM "Cannot create $OUTDIR" "Disk full or permission denied." "free space or set another HOME"
  cd "$OUTDIR" || die ERR_PERM "Cannot enter $OUTDIR" "Not accessible." "check permissions"
  LOG="$OUTDIR/run.log"; : > "$LOG"
  local SUBS=subs.txt RES=resolved.txt NONCDN=non_cdn.txt CAND=candidates.txt RPT=REPORT.md JSON=results.json
  : > "$SUBS"; : > "$RES"; : > "$NONCDN"; : > "$CAND"; : > asn_cache.txt; : > dead_ips.txt
  score_py; PHASE_NAME=""; SCAN_START=$SECONDS

  phase "wildcard check"
  local RND="bs$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  WILD_IP="$(dig +short A "$RND.$DOMAIN" 2>/dev/null | head -1)"
  if [ -n "$WILD_IP" ]; then
    warn "wildcard *.$DOMAIN -> $WILD_IP (brute gets noisy)"
    ok "wildcard IP $WILD_IP excluded from all candidates"
  else ok "no wildcard"; WILD_IP=""; fi

  phase "passive collection (parallel)"
  mkdir -p src
  ( fetch "https://crt.sh/?q=%25.$DOMAIN&output=json" ct.json 120 && jq -r '.[].name_value' ct.json 2>/dev/null | tr ',' '\n' | collect_to src/crtsh ) &
  ( fetch "https://api.certspotter.com/v1/issuances?domain=$DOMAIN&include_subdomains=true&expand=dns_names" cs.json 60 && jq -r '.[].dns_names[]' cs.json 2>/dev/null | collect_to src/certspotter ) &
  ( fetch "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=100" us.json 60 && jq -r '.results[].page.domain' us.json 2>/dev/null | collect_to src/urlscan ) &
  ( fetch "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" ht.txt 60 && cut -d, -f1 ht.txt | collect_to src/hackertarget ) &
  ( fetch "https://rapiddns.io/subdomain/$DOMAIN?full=1" rd.html 60 && grep -oE "[a-z0-9_-]+\.$DOMAIN" rd.html | collect_to src/rapiddns ) &
  ( fetch "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN&output=txt&fl=original&collapse=urlkey&limit=5000" wb.txt 120 && \
    { if have unfurl; then unfurl -u domains < wb.txt; else grep -oE "[a-z0-9_-]+\.$DOMAIN" wb.txt; fi; } | collect_to src/wayback ) &
  ( fetch "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" otx.json 60 1 && \
    { jq -r '.passive_dns[].hostname' otx.json 2>/dev/null | collect_to src/otx;
      jq -r '.passive_dns[].address' otx.json 2>/dev/null | sort -u > otx_ips.txt; } ) &
  ( [ -n "${VT_KEY:-}" ] && curl -fsSL --max-time 25 -A "$UA" -H "x-apikey: $VT_KEY" \
      "https://www.virustotal.com/api/v3/domains/$DOMAIN/resolutions?limit=40" -o vt.json 2>>"$LOG" \
    && jq -r '.data[].attributes.ip_address' vt.json 2>/dev/null | sort -u > vt_ips.txt || true ) &
  ( [ -n "${ST_KEY:-}" ] && fetch "https://api.securitytrails.com/v1/history/$DOMAIN/dns/a" st.json 60 \
    && jq -r '.records[].values[].ip' st.json 2>/dev/null | sort -u > st_ips.txt || true ) &
  ( curl -fsSL --max-time 25 -A "$UA" -H "Referer: https://viewdns.info/" "https://viewdns.info/iphistory/?domain=$DOMAIN" -o vd.html 2>>"$LOG" \
    && grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' vd.html | sort -u > viewdns_ips.txt || true ) &
  ( local u
    for u in "https://$DOMAIN/" "https://$DOMAIN/auth/register" "https://$DOMAIN/login" "https://$DOMAIN/robots.txt" "https://$DOMAIN/sitemap.xml"; do
      curl -fsSkL --max-time 25 -A "$UA" "$u" 2>>"$LOG" | grep -oE "https?://[a-z0-9._-]+" | sed 's#https\?://##' | collect_to src/livepages
    done ) &
  ( have subfinder && timeout 300 subfinder -d "$DOMAIN" -all -recursive -silent 2>>"$LOG" | collect_to src/subfinder || true ) &
  ( have assetfinder && timeout 120 assetfinder --subs-only "$DOMAIN" 2>>"$LOG" | collect_to src/assetfinder || true ) &
  ( local ns
    for ns in $(dig +short NS "$DOMAIN" 2>/dev/null | sed 's/\.$//'); do
      timeout 10 dig +retry=0 +time=5 AXFR "$DOMAIN" "@$ns" 2>>"$LOG" | grep -oE "[a-z0-9._-]+\.$DOMAIN" | collect_to src/axfr
    done; true ) &

  { dig +short MX "$DOMAIN"; dig +short NS "$DOMAIN"; dig +short TXT "$DOMAIN"; } 2>/dev/null > dns_meta.txt
  dig +short MX "$DOMAIN" 2>/dev/null | awk '{print $2}' | sed 's/\.$//' | collect_to src/dnsmx
  dig +short TXT "$DOMAIN" 2>/dev/null | grep -oE 'include:[a-z0-9._-]+' | cut -d: -f2 | collect_to src/dnstxt
  dig +short TXT "$DOMAIN" | grep -oE "ip4:[0-9.]+" | cut -d: -f2 > spf_ips.txt

  wait
  cat src/* 2>/dev/null > "$SUBS"
  sort -u "$SUBS" -o "$SUBS"
  local s_axfr; s_axfr="$(wc -l < src/axfr 2>/dev/null || echo 0)"
  [ "$s_axfr" -gt 0 ] && ok "AXFR leak: $s_axfr names from zone transfer" || log "no AXFR leak"
  ok "$(wc -l < "$SUBS") unique names"

  phase "direct-host probes"
  printf '%s\n' direct origin srv server host backend web web1 ns1 ns2 mail smtp ftp cpanel webmail \
    dev staging stage old backup legacy portal panel manage admin api git mc vpn internal \
    | sed "s/$/.$DOMAIN/" >> "$SUBS"; sort -u "$SUBS" -o "$SUBS"
  ok "$(wc -l < "$SUBS") names incl. probes"

  if [ "$BRUTE" = 1 ] && [ "$QUICK" = 0 ] && have puredns && [ -s "$RESOLVERS" ]; then
    phase "brute force"
    local WL="" c
    for c in /usr/share/seclists/Discovery/DNS/subdomains-top1million-11000.txt \
             "$CONF_DIR/SecLists/Discovery/DNS/subdomains-top1million-11000.txt" \
             /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
             "$CONF_DIR/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"; do
      [ -f "$c" ] && WL="$c" && break
    done
    if [ -n "$WL" ]; then
      log "$(basename "$WL")"
      timeout 900 puredns bruteforce "$WL" "$DOMAIN" -r "$RESOLVERS" -w brute.txt >/dev/null 2>>"$LOG" \
        || err ERR_DNS "puredns failed" "Resolvers exhausted or timed out." "refresh $RESOLVERS"
      [ -s brute.txt ] && { cat brute.txt | collect_to brute.f; cat brute.f >> "$SUBS"; sort -u "$SUBS" -o "$SUBS"; ok "brute: $(wc -l < brute.f) hits"; }
    else err ERR_NOWL "No wordlist" "SecLists missing." "sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists"; fi
  else warn "brute skipped"; fi

  phase "resolution"
  [ -s "$SUBS" ] || die ERR_NOIP "Nothing to resolve" "All passive sources empty." "confirm the domain is live: dig $DOMAIN"
  log "resolving $(wc -l < "$SUBS") names"
  if have dnsx; then
    timeout 600 dnsx -l "$SUBS" -a -resp -silent -t "$THREADS" 2>>"$LOG" | tr -d '[]' | awk 'NF>=2{print $1" "$2}' | sort -u > "$RES"
  else
    xargs -r -n1 -P "$THREADS" bash -c \
      'for ip in $(timeout 8 dig +short A "$1" 2>/dev/null); do printf "%s %s\n" "$1" "$ip"; done' _ < "$SUBS" | sort -u > "$RES"
  fi
  [ -s "$RES" ] || die ERR_DNS "No A records" "Names collected, none resolve." "try: dig @1.1.1.1 $DOMAIN"
  ok "$(wc -l < "$RES") A records"

  phase "ASN classification (local CF ranges + /24 cache)"
  : > classified.txt; : > "$NONCDN"
  export -f classify_one classify_cached classify asn_of cf_has ip_in_cidr
  export CF_RANGES
  xargs -r -n2 -P "$THREADS" bash -c 'classify_one "$1" "$2"' _ < "$RES" > classified.txt 2>>"$LOG"
  awk '$3!="cloudflare" && $3!="cdn" {print $1" "$2}' classified.txt > "$NONCDN"
  local n; n="$(wc -l < "$NONCDN")"
  [ "$n" -gt 0 ] && ok "$n non-CDN records" || err ERR_NOIP "Everything on Cloudflare/CDN" "No hostname leaks the origin." "history check follows"

  phase "baseline fingerprint"
  local BASE=base.html BASEH=base.headers BASEFAV=base.favicon BC BS
  BC="$(curl -skL --max-time 25 -A "$UA" -D "$BASEH" -o "$BASE" -w '%{http_code}' "https://$DOMAIN/" 2>>"$LOG")"
  BC="${BC:-000}"; BS="$(wc -c < "$BASE" 2>/dev/null || echo 0)"
  curl -skL --max-time 12 -A "$UA" -o "$BASEFAV" "https://$DOMAIN/favicon.ico" 2>>"$LOG" || true
  if [ "$BC" = "000" ]; then err ERR_BASE "Baseline fetch failed" "DNS, TLS or timeout on https://$DOMAIN." "check it loads in a browser"
  else
    ok "baseline HTTP $BC, ${BS}b"
    grep -qi '^cf-ray:' "$BASEH" && ok "target confirmed behind Cloudflare (cf-ray present)" || warn "no cf-ray header — target may not use Cloudflare"
    [ -s "$BASEFAV" ] && ok "baseline favicon captured ($(sha256sum "$BASEFAV" | cut -c1-12))"
  fi

  phase "origin verification (multi-signal, parallel)"
  printf '%-40s %-16s %-10s %-5s %-5s %-5s %-8s %s\n' HOST IP CLASS CODE SCORE PROB VERDICT EVIDENCE > "$CAND"
  export CAND LOG BASE BASEH BASEFAV DOMAIN UA WILD_IP OUTDIR THREADS
  export -f verify_host cert_match ok warn log
  log "verifying $(wc -l < "$NONCDN") hosts with $THREADS workers"
  xargs -r -n2 -P "$THREADS" bash -c 'verify_host "$1" "$2"' _ < "$NONCDN" 2>>"$LOG"
  ok "verified $(($(wc -l < "$CAND") - 1)) candidates"

  phase "API intelligence"
  if [ -n "${SHODAN_KEY:-}" ]; then
    touch shodan_ips.txt fav_shodan_ips.txt
    local q code hit=0
    for q in "hostname%3A%22.${DOMAIN}%22" "ssl.cert.subject.CN%3A%22${DOMAIN}%22" "ssl%3A%22${DOMAIN}%22"; do
      code="$(curl -s --max-time 60 "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=${q}" -o shodan.json -w '%{http_code}' 2>>"$LOG")"
      if [ "$code" = "200" ]; then
        jq -r '.matches[].ip_str' shodan.json 2>/dev/null | sort -u > shodan_ips.txt
        if [ -s shodan_ips.txt ]; then hit=1; ok "shodan: $(wc -l < shodan_ips.txt) IPs"; break; fi
      else
        case "$code" in
          401) warn "shodan HTTP 401 — key invalid; run: backscrape --reconfigure-apis"; break ;;
          402) warn "shodan HTTP 402 — search needs paid credits (one-time plan); other sources still active"; break ;;
          429) warn "shodan HTTP 429 — rate limited; retry later"; break ;;
          403) warn "shodan HTTP 403 — key invalid or blocked; run: backscrape --reconfigure-apis"; break ;;
          *)   warn "shodan HTTP $code" ;;
        esac
      fi
    done
    [ "$hit" = 0 ] && [ "${code:-}" = "200" ] && warn "shodan returned no IPs for any query"
    local FH
    FH="$(python3 - "$DOMAIN" <<'PYH' 2>/dev/null
import sys, ssl, urllib.request, hashlib, codecs
try:
    import mmh3
except Exception:
    sys.exit(0)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    r = urllib.request.Request("https://%s/favicon.ico" % sys.argv[1], headers={'User-Agent': 'Mozilla/5.0'})
    b = urllib.request.urlopen(r, timeout=15, context=ctx).read()
    print(mmh3.hash(codecs.encode(hashlib.md5(b).hexdigest(), 'base64')))
except Exception:
    pass
PYH
)"
    if [ -n "$FH" ]; then
      log "favicon hash $FH — hunting origins"
      code="$(curl -s --max-time 60 "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=http.favicon.hash%3A${FH}" -o fav.json -w '%{http_code}' 2>>"$LOG")"
      if [ "$code" = "200" ]; then
        jq -r '.matches[].ip_str' fav.json 2>/dev/null | sort -u > fav_shodan_ips.txt
        [ -s fav_shodan_ips.txt ] && ok "favicon hunt: $(wc -l < fav_shodan_ips.txt) IPs"
      else warn "favicon hunt HTTP $code"; fi
    else warn "favicon hunt unavailable (mmh3 missing) — skipped"; fi
  else warn "no SHODAN key — shodan phases skipped (backscrape --reconfigure-apis)"; fi

  if [ -n "${CENSYS_TOKEN:-}" ]; then
    touch censys_ips.txt
    local cb cq code okc=0
    cb="$(printf '%s' "$CENSYS_TOKEN" | tr -d '\n' | base64 | tr -d '\n')"
    for cq in "names: ${DOMAIN}" "services.tls.certificates.leaf_data.names: ${DOMAIN}"; do
      code="$(curl -s --max-time 60 -H "Authorization: Basic $cb" -H "Content-Type: application/json" \
        "https://search.censys.io/api/v2/hosts/search" \
        -d "$(jq -nc --arg q "$cq" '{q:$q,per_page:50}')" -o censys.json -w '%{http_code}' 2>>"$LOG")"
      if [ "$code" = "200" ]; then
        jq -r '.result.hits[].ip' censys.json 2>/dev/null | sort -u > censys_ips.txt
        if [ -s censys_ips.txt ]; then okc=1; ok "censys: $(wc -l < censys_ips.txt) IPs"; break; fi
      else
        case "$code" in
          401|403) warn "censys HTTP $code — credentials must be API_ID:SECRET; run: backscrape --reconfigure-apis"; break ;;
          429) warn "censys HTTP 429 — rate limited"; break ;;
          *) warn "censys HTTP $code" ;;
        esac
      fi
    done
    [ "$okc" = 0 ] && [ "${code:-}" = "200" ] && warn "censys returned no IPs"
  else warn "no CENSYS key — censys phase skipped (backscrape --reconfigure-apis)"; fi

  phase "historical IP verification (parallel)"
  cat st_ips.txt vt_ips.txt viewdns_ips.txt spf_ips.txt shodan_ips.txt censys_ips.txt fav_shodan_ips.txt otx_ips.txt 2>/dev/null \
    | sort -u | grep -vF "$WILD_IP" > hist_ips.txt || true
  local ip
  : > hist_todo.txt
  while read -r ip; do
    [ -n "$ip" ] || continue
    grep -qxF "$ip" dead_ips.txt 2>/dev/null && continue
    if cf_has "$ip"; then continue; fi
    cls="$(classify_cached "$ip")"
    case "$cls" in cloudflare|cdn) continue ;; esac
    printf '%s %s\n' "$DOMAIN" "$ip" >> hist_todo.txt
  done < hist_ips.txt
  if [ -s hist_todo.txt ]; then
    log "verifying $(wc -l < hist_todo.txt) historical/API IPs with $THREADS workers"
    xargs -r -n2 -P "$THREADS" bash -c 'verify_host "$1" "$2"' _ < hist_todo.txt 2>>"$LOG"
  else ok "no new historical/API IPs to verify"; fi

  phase "verdict"
  local REAL LIKELY top ipaddr conf
  REAL="$(awk '$7=="REAL"'   "$CAND" | sort -k6 -nr)"
  LIKELY="$(awk '$7=="LIKELY"' "$CAND" | sort -k6 -nr)"

  if [ -n "$REAL" ]; then
    top="$(printf '%s\n' "$REAL" | head -1)"
    ipaddr="$(printf '%s' "$top" | awk '{print $2}')"
    conf="$(printf '%s' "$top" | awk '{print $6}')"
    printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_GRN$C_B" "$C_R"
    printf '%s║%s  %sORIGIN FOUND%s                                              %s║%s\n' "$C_GRN$C_B" "$C_R" "$C_B$C_GRN" "$C_R" "$C_GRN$C_B" "$C_R"
    printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$C_GRN$C_B" "$C_R"
    printf '\n   %sORIGIN IP:%s  %s%s%s\n' "$C_B" "$C_R" "$C_B$C_CYN" "$ipaddr" "$C_R"
    printf '   %sPROBABILITY:%s %s %s\n' "$C_B" "$C_R" "$(pscale "$conf")" "$(p_label "$conf")"
    printf '   %sevidence:%s %s\n' "$C_DIM" "$C_R" "$(printf '%s' "$top" | cut -d' ' -f8-)"
    printf '   %sasn:%s %s\n' "$C_DIM" "$C_R" "$(asn_of "$ipaddr" | awk -F'|' '{print $1" — "$NF}' | sed 's/^ *//')"
    printf '\n   %sverify:%s curl -sk --resolve %s:443:%s https://%s/ | head -40\n\n' "$C_DIM" "$C_R" "$DOMAIN" "$ipaddr" "$DOMAIN"
    printf '%s\n' "$REAL" | awk 'NR>1{printf "   also: %s -> %s (probability %s%%)\n", $1, $2, $6}'
  elif [ -n "$LIKELY" ]; then
    top="$(printf '%s\n' "$LIKELY" | head -1)"
    ipaddr="$(printf '%s' "$top" | awk '{print $2}')"
    conf="$(printf '%s' "$top" | awk '{print $6}')"
    if [ "$conf" -ge 70 ] 2>/dev/null; then
      printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_YEL$C_B" "$C_R"
      printf '%s║%s  %sPOSSIBLE ORIGIN (unconfirmed)%s                          %s║%s\n' "$C_YEL$C_B" "$C_R" "$C_B$C_YEL" "$C_R" "$C_YEL$C_B" "$C_R"
      printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$C_YEL$C_B" "$C_R"
      printf '\n   %sCANDIDATE IP:%s  %s%s%s\n' "$C_B" "$C_R" "$C_B$C_YEL" "$ipaddr" "$C_R"
      printf '   %sPROBABILITY:%s %s %s\n' "$C_B" "$C_R" "$(pscale "$conf")" "$(p_label "$conf")"
      printf '   %sevidence:%s %s\n' "$C_DIM" "$C_R" "$(printf '%s' "$top" | cut -d' ' -f8-)"
      printf '\n   %sverify manually:%s curl -sk --resolve %s:443:%s https://%s/ | head -40\n' "$C_DIM" "$C_R" "$DOMAIN" "$ipaddr" "$DOMAIN"
      printf '   %s(add an API key for stronger confirmation: backscrape --reconfigure-apis)%s\n\n' "$C_DIM" "$C_R"
    else
      printf '\n   %sBEST CANDIDATE:%s  %s%s%s\n' "$C_B" "$C_R" "$C_B$C_YEL" "$ipaddr" "$C_R"
      printf '   %sPROBABILITY:%s %s %s\n\n' "$C_B" "$C_R" "$(pscale "$conf")" "$(p_label "$conf")"
      err ERR_NOIP "No confirmed origin" "Top candidates reached LIKELY only." "inspect $CAND; top rows are best leads"
    fi
  else
    printf '\n   %sPROBABILITY:%s %s %s\n\n' "$C_B" "$C_R" "$(pscale 10)" "$(p_label 10)"
    err ERR_INCONCLUSIVE "No candidate confirmed" "No signals lined up above threshold." "review REPORT.md; verify via authorized hosting/CDN accounts"
  fi

  {
    echo "# backscrape — $DOMAIN"; echo
    echo "\`$(date -u '+%Y-%m-%d %H:%M UTC')\` · v$VERSION · **$AUTHOR** · runtime $((SECONDS - SCAN_START))s"; echo
    echo "## Verdict"; echo
    if [ -n "$REAL" ]; then
      echo "ORIGIN IP: \`$ipaddr\` — probability **${conf}%**"; echo
      echo '```'; printf '%s\n' "$REAL"; echo '```'
    elif [ -n "$LIKELY" ]; then
      echo "POSSIBLE ORIGIN: \`$ipaddr\` — probability **${conf}%** (unconfirmed)"; echo
      echo '```'; printf '%s\n' "$LIKELY" | head -10; echo '```'
    else
      echo "no confirmed origin"
    fi
    echo
    echo "## Candidates (score / probability / evidence)"; echo; echo '```'; cat "$CAND"; echo '```'; echo
    echo "## DNS metadata"; echo; echo '```'; cat dns_meta.txt; echo '```'; echo
    echo "## Resolved"; echo; echo '```'; cat "$RES"; echo '```'
  } > "$RPT"
  jq -n --arg d "$DOMAIN" --arg t "$(date -u +%FT%TZ)" --arg v "$VERSION" \
    --argjson s "$((SECONDS - SCAN_START))" --rawfile c "$CAND" --rawfile m dns_meta.txt \
    '{domain:$d, tool:"backscrape", version:$v, generated:$t, runtime_s:$s, candidates:$c, dns_meta:$m}' > "$JSON"
  printf '  %s⏱ total %ss · report %s · json %s%s\n\n' "$C_DIM" "$((SECONDS - SCAN_START))" "$RPT" "$JSON" "$C_R"
}

RECONFIGURE_APIS=0; CLI_DOMAIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --pause) PAUSE=1 ;;
    --reconfigure-apis) RECONFIGURE_APIS=1 ;;
    --domain) CLI_DOMAIN="${2:-}"; shift ;;
    --threads) THREADS="${2:-30}"; shift ;;
    --no-brute) BRUTE=0 ;;
    --quick) QUICK=1; BRUTE=0 ;;
    --version|-V) printf 'backscrape v%s by %s\n' "$VERSION" "$AUTHOR"; exit 0 ;;
    -h|--help)
      printf 'backscrape v%s — domain origin audit (by %s).\n\n' "$VERSION" "$AUTHOR"
      printf '  backscrape                        interactive mode\n'
      printf '  backscrape --domain example.com   scan without prompts\n'
      printf '  backscrape --threads 60           parallel workers (default 30)\n'
      printf '  backscrape --no-brute             skip DNS brute force\n'
      printf '  backscrape --quick                fast mode (no brute)\n'
      printf '  backscrape --pause                keep terminal open on exit\n'
      printf '  backscrape --reconfigure-apis     change saved API keys\n'
      printf '  backscrape --version              show version\n'
      exit 0 ;;
    *) printf 'Unknown option: %s\nUse: backscrape --help\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

norm() { local d="$1"; d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"; d="${d%% *}"; printf '%s' "$d" | tr 'A-Z' 'a-z'; }
valid() { printf '%s' "$1" | grep -qE '^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$'; }

banner
accept_disclaimer
bootstrap

if [ -n "$CLI_DOMAIN" ]; then
  DOMAIN="$(norm "$CLI_DOMAIN")"
  valid "$DOMAIN" || die ERR_ARG "Not a domain: '$CLI_DOMAIN'" "Expected example.com" "retype it"
  printf '  %starget%s  %s%s%s\n' "$C_B" "$C_R" "$C_B$C_CYN" "$DOMAIN" "$C_R"
  run_scan
else
  while :; do
    hr
    printf '  %senter target URL or domain%s  %s(q to quit)%s\n' "$C_B" "$C_R" "$C_DIM" "$C_R"
    while :; do
      printf '\n  %s> %s' "$C_CYN" "$C_R"
      read -r RAW || exit 0
      [ -z "${RAW:-}" ] && { warn "empty"; continue; }
      case "${RAW,,}" in q|quit|exit) printf '\n  %sbye%s\n\n' "$C_DIM" "$C_R"; exit 0 ;; esac
      DOMAIN="$(norm "$RAW")"
      valid "$DOMAIN" && break
      err ERR_ARG "Not a domain: '$RAW'" "Expected https://example.com or example.com" "retype it"
    done
    hr
    printf '  %starget%s  %s%s%s\n' "$C_B" "$C_R" "$C_B$C_CYN" "$DOMAIN" "$C_R"
    printf '  %sbrute in 5s, n to skip...%s ' "$C_DIM" "$C_R"
    ans=""; read -t 5 -r ans 2>/dev/null || true
    case "${ans:-y}" in [Nn]*) BRUTE=0; printf '\n  brute %soff%s\n' "$C_YEL" "$C_R" ;; *) BRUTE=1; printf '\n  brute %son%s\n' "$C_GRN" "$C_R" ;; esac
    sleep 1
    run_scan
    printf '  %sanother? [y/N] %s' "$C_B" "$C_R"
    ans=""; read -r ans 2>/dev/null || true
    case "${ans:-n}" in [Yy]*) banner ;; *) printf '\n  %sbye — %s%s\n\n' "$C_DIM" "$AUTHOR" "$C_R"; break ;; esac
  done
fi

[ "$PAUSE" = 1 ] && { printf "  press enter to close"; read -r _; }
