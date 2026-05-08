#!/usr/bin/env bash
#
# Helpers for the temporary env file passed to `docker compose --env-file`.

read_env_value() {
    local key="$1"
    local env_file="${2:-$APP_ENV_FILE}"
    local line
    line="$(grep -m1 "^${key}=" "$env_file" 2>/dev/null || true)"
    [ -n "$line" ] || return 1
    printf '%s' "${line#*=}"
}

compose_env_escape() {
    printf '%s' "$1" | sed 's/\$/\$\$/g'
}

write_compose_env_value() {
    local key="$1"
    local value="$2"

    case "$value" in
        *$'\n'*|*$'\r'*)
            echo "[deploy] refusing multi-line compose env value for $key" >&2
            return 1
            ;;
    esac

    printf '%s=%s\n' "$key" "$(compose_env_escape "$value")"
}

write_compose_env_file() {
    local output_file="$1"
    local app_env_file="$2"
    local tunnel_token

    {
        write_compose_env_value APP_ENV_FILE "$app_env_file"
        if [ -n "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]; then
            write_compose_env_value CLOUDFLARE_TUNNEL_TOKEN "$CLOUDFLARE_TUNNEL_TOKEN"
        elif tunnel_token="$(read_env_value CLOUDFLARE_TUNNEL_TOKEN "$app_env_file")"; then
            write_compose_env_value CLOUDFLARE_TUNNEL_TOKEN "$tunnel_token"
        fi
    } > "$output_file"
}
