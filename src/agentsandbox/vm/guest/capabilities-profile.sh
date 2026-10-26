# Sourced by login shells: exports the capability placeholders the host
# delivered for this session, so `echo $GITHUB_TOKEN` just works.
#
# `asbx cap sync` can rewrite the file while a shell is open (a new secret,
# a renamed variable). In an interactive bash, the next prompt notices the
# file was replaced, drops the variables the old file exported, sources the
# new one, and says so - instead of the shell silently running on stale
# placeholders. Other shells, and processes already started, keep what they
# had until they are restarted.
_asbx_env=/run/asbx/capabilities.env
_asbx_env_names() {
    sed -n 's/^export \([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$_asbx_env" 2>/dev/null
}
[ -r "$_asbx_env" ] && . "$_asbx_env"

if [ -n "${BASH_VERSION:-}" ] && [ -n "${PS1:-}" ]; then
    _asbx_env_seen=$(stat -c '%i %Y' "$_asbx_env" 2>/dev/null)
    _asbx_env_had=$(_asbx_env_names)
    _asbx_env_reload() {
        local now
        now=$(stat -c '%i %Y' "$_asbx_env" 2>/dev/null) || return 0
        [ "$now" = "$_asbx_env_seen" ] && return 0
        _asbx_env_seen=$now
        [ -n "$_asbx_env_had" ] && unset $_asbx_env_had
        . "$_asbx_env"
        _asbx_env_had=$(_asbx_env_names)
        echo "asbx: capabilities changed on the host - reloaded $_asbx_env (processes started earlier still have the old values)" >&2
    }
    PROMPT_COMMAND="_asbx_env_reload${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
fi
