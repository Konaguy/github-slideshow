#!/usr/bin/env bash
# scope-guard: filter a stream of hosts/URLs against an in-scope allowlist.
# Every active agent should pipe target lists through this before probing so
# out-of-scope assets can never be touched by accident.
#
# Usage:
#   subfinder -d example.com -silent | scope-guard.sh scope.txt | httpx ...
#   echo "https://api.example.com/x" | scope-guard.sh scope.txt
#
# scope.txt: one in-scope root per line. Supports:
#   example.com        -> matches example.com and *.example.com
#   *.example.com      -> matches subdomains only
#   1.2.3.4            -> exact host/IP
#   # comments and blank lines ignored
# Lines that don't match any rule are dropped and logged to stderr.
set -uo pipefail

SCOPE="${1:-scope.txt}"
[ -f "$SCOPE" ] || { echo "scope-guard: scope file '$SCOPE' not found" >&2; exit 2; }

# Load rules into a regex alternation.
mapfile -t RULES < <(grep -vE '^\s*(#|$)' "$SCOPE" | sed 's/[[:space:]]//g')
[ "${#RULES[@]}" -gt 0 ] || { echo "scope-guard: no rules in '$SCOPE'" >&2; exit 2; }

host_of() { # extract host from a URL or bare host:port
  local s="$1"
  s="${s#*://}"; s="${s%%/*}"; s="${s%%\?*}"; s="${s%%:*}"
  printf '%s' "$s" | tr 'A-Z' 'a-z'
}

in_scope() {
  local host="$1" rule base
  for rule in "${RULES[@]}"; do
    rule="$(printf '%s' "$rule" | tr 'A-Z' 'a-z')"
    case "$rule" in
      \*.*) base="${rule#\*.}"; [ "$host" != "$base" ] && [[ "$host" == *".$base" ]] && return 0 ;;
      *)    [ "$host" = "$rule" ] && return 0
            [[ "$host" == *".$rule" ]] && return 0 ;;
    esac
  done
  return 1
}

kept=0; dropped=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  h="$(host_of "$line")"
  if in_scope "$h"; then printf '%s\n' "$line"; kept=$((kept+1))
  else echo "scope-guard: DROP out-of-scope: $line" >&2; dropped=$((dropped+1)); fi
done
echo "scope-guard: kept=$kept dropped=$dropped" >&2
