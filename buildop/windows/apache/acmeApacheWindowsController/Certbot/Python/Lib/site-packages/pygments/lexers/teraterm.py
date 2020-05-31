# -*- coding: utf-8 -*-
"""
    pygments.lexers.teraterm
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Lexer for Tera Term macro files.

    :copyright: Copyright 2006-2019 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

import re

from pygments.lexer import RegexLexer, include, bygroups
from pygments.token import Text, Comment, Operator, Name, String, \
    Number, Keyword

__all__ = ['TeraTermLexer']


class TeraTermLexer(RegexLexer):
    """
    For `Tera Term <https://ttssh2.osdn.jp/>`_ macro source code.

    .. versionadded:: 2.4
    """
    name = 'Tera Term macro'
    aliases = ['ttl', 'teraterm', 'teratermmacro']
    filenames = ['*.ttl']
    mimetypes = ['text/x-teratermmacro']

    tokens = {
        'root': [
            include('comments'),
            include('labels'),
            include('commands'),
            include('builtin-variables'),
            include('user-variables'),
            include('operators'),
            include('numeric-literals'),
            include('string-literals'),
            include('all-whitespace'),
            (r'[^\s]', Text),
        ],
        'comments': [
            (r';[^\r\n]*', Comment.Single),
            (r'/\*', Comment.Multiline, 'in-comment'),
        ],
        'in-comment': [
            (r'\*/', Comment.Multiline, '#pop'),
            (r'[^*/]+', Comment.Multiline),
            (r'[*/]', Comment.Multiline)
        ],
        'labels': [
            (r'(?i)^(\s*)(:[0-9a-z_]+)', bygroups(Text, Name.Label)),
        ],
        'commands': [
            (
                r'(?i)\b('
                r'basename|beep|bplusrecv|bplussend|break|bringupbox|'
                r'callmenu|changedir|checksum16|checksum16file|'
                r'checksum32|checksum32file|checksum8|checksum8file|'
                r'clearscreen|clipb2var|closesbox|closett|code2str|'
                r'connect|continue|crc16|crc16file|crc32|crc32file|'
                r'cygconnect|delpassword|dirname|dirnamebox|disconnect|'
                r'dispstr|do|else|elseif|enablekeyb|end|endif|enduntil|'
                r'endwhile|exec|execcmnd|exit|expandenv|fileclose|'
                r'fileconcat|filecopy|filecreate|filedelete|filelock|'
                r'filemarkptr|filenamebox|fileopen|fileread|filereadln|'
                r'filerename|filesearch|fileseek|fileseekback|filestat|'
                r'filestrseek|filestrseek2|filetruncate|fileunlock|'
                r'filewrite|filewriteln|findclose|findfirst|findnext|'
                r'flushrecv|foldercreate|folderdelete|foldersearch|for|'
                r'getdate|getdir|getenv|getfileattr|gethostname|'
                r'getipv4addr|getipv6addr|getmodemstatus|getpassword|'
                r'getspecialfolder|gettime|gettitle|getttdir|getver|'
                r'if|ifdefined|include|inputbox|int2str|intdim|'
                r'ispassword|kmtfinish|kmtget|kmtrecv|kmtsend|listbox|'
                r'loadkeymap|logautoclosemode|logclose|loginfo|logopen|'
                r'logpause|logrotate|logstart|logwrite|loop|makepath|'
                r'messagebox|mpause|next|passwordbox|pause|quickvanrecv|'
                r'quickvansend|random|recvln|regexoption|restoresetup|'
                r'return|rotateleft|rotateright|scprecv|scpsend|send|'
                r'sendbreak|sendbroadcast|sendfile|sendkcode|sendln|'
                r'sendlnbroadcast|sendlnmulticast|sendmulticast|setbaud|'
                r'setdate|setdebug|setdir|setdlgpos|setdtr|setecho|'
                r'setenv|setexitcode|setfileattr|setflowctrl|'
                r'setmulticastname|setpassword|setrts|setsync|settime|'
                r'settitle|show|showtt|sprintf|sprintf2|statusbox|'
                r'str2code|str2int|strcompare|strconcat|strcopy|strdim|'
                r'strinsert|strjoin|strlen|strmatch|strremove|'
                r'strreplace|strscan|strspecial|strsplit|strtrim|'
                r'testlink|then|tolower|toupper|unlink|until|uptime|'
                r'var2clipb|wait|wait4all|waitevent|waitln|waitn|'
                r'waitrecv|waitregex|while|xmodemrecv|xmodemsend|'
                r'yesnobox|ymodemrecv|ymodemsend|zmodemrecv|zmodemsend'
                r')\b',
                Keyword,
            ),
            (
                r'(?i)(call|goto)([ \t]+)([0-9a-z_]+)',
                bygroups(Keyword, Text, Name.Label),
            )
        ],
        'builtin-variables': [
            (
                r'(?i)('
                r'groupmatchstr1|groupmatchstr2|groupmatchstr3|'
                r'groupmatchstr4|groupmatchstr5|groupmatchstr6|'
                r'groupmatchstr7|groupmatchstr8|groupmatchstr9|'
                r'param1|param2|param3|param4|param5|param6|'
                r'param7|param8|param9|paramcnt|params|'
                r'inputstr|matchstr|mtimeout|result|timeout'
                r')\b',
                Name.Builtin
            ),
        ],
        'user-variables': [
            (r'(?i)[A-Z_][A-Z0-9_]*', Name.Variable),
        ],
        'numeric-literals': [
            (r'(-?)([0-9]+)', bygroups(Operator, Number.Integer)),
            (r'(?i)\$[0-9a-f]+', Number.Hex),
        ],
        'string-literals': [
            (r'(?i)#(?:[0-9]+|\$[0-9a-f]+)', String.Char),
            (r"'", String.Single, 'in-single-string'),
            (r'"', String.Double, 'in-double-string'),
        ],
        'in-general-string': [
            (r'[\\][\\nt]', String.Escape),  # Only three escapes are supported.
            (r'.', String),
        ],
        'in-single-string': [
            (r"'", String.Single, '#pop'),
            include('in-general-string'),
        ],
        'in-double-string': [
            (r'"', String.Double, '#pop'),
            include('in-general-string'),
        ],
        'operators': [
            (r'and|not|or|xor', Operator.Word),
            (r'[!%&*+<=>^~\|\/-]+', Operator),
            (r'[()]', String.Symbol),
        ],
        'all-whitespace': [
            (r'[\s]+', Text),
        ],
    }

    # Turtle and Tera Term macro files share the same file extension
    # but each has a recognizable and distinct syntax.
    def analyse_text(text):
        result = 0.0
        if re.search(TeraTermLexer.tokens['commands'][0][0], text):
            result += 0.01
        return result
