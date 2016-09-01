#!/usr/bin/bash

_script()
{
        DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
        _script_commands=$(cat "${DIR}/.enpassant")

        local cur prev
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        COMPREPLY=( $(compgen -W "${_script_commands}" -- ${cur}) )

        return 0
}

complete -o nospace -F _script pass


# .bashrc
# alias pass=/enpass-decryptor/enpassant.py
# source /enpass-decryptor/autocomplete.sh
