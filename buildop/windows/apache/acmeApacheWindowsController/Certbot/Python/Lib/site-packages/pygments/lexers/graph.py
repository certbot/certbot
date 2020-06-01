# -*- coding: utf-8 -*-
"""
    pygments.lexers.graph
    ~~~~~~~~~~~~~~~~~~~~~

    Lexers for graph query languages.

    :copyright: Copyright 2006-2019 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

import re

from pygments.lexer import RegexLexer, include, bygroups, using, this
from pygments.token import Keyword, Punctuation, Comment, Operator, Name,\
    String, Number, Whitespace


__all__ = ['CypherLexer']


class CypherLexer(RegexLexer):
    """
    For `Cypher Query Language
    <https://neo4j.com/docs/developer-manual/3.3/cypher/>`_

    For the Cypher version in Neo4j 3.3

    .. versionadded:: 2.0
    """
    name = 'Cypher'
    aliases = ['cypher']
    filenames = ['*.cyp', '*.cypher']

    flags = re.MULTILINE | re.IGNORECASE

    tokens = {
        'root': [
            include('comment'),
            include('keywords'),
            include('clauses'),
            include('relations'),
            include('strings'),
            include('whitespace'),
            include('barewords'),
        ],
        'comment': [
            (r'^.*//.*\n', Comment.Single),
        ],
        'keywords': [
            (r'(create|order|match|limit|set|skip|start|return|with|where|'
             r'delete|foreach|not|by|true|false)\b', Keyword),
        ],
        'clauses': [
            # based on https://neo4j.com/docs/cypher-refcard/3.3/
            (r'(all|any|as|asc|ascending|assert|call|case|create|'
             r'create\s+index|create\s+unique|delete|desc|descending|'
             r'distinct|drop\s+constraint\s+on|drop\s+index\s+on|end|'
             r'ends\s+with|fieldterminator|foreach|in|is\s+node\s+key|'
             r'is\s+null|is\s+unique|limit|load\s+csv\s+from|match|merge|none|'
             r'not|null|on\s+match|on\s+create|optional\s+match|order\s+by|'
             r'remove|return|set|skip|single|start|starts\s+with|then|union|'
             r'union\s+all|unwind|using\s+periodic\s+commit|yield|where|when|'
             r'with)\b', Keyword),
        ],
        'relations': [
            (r'(-\[)(.*?)(\]->)', bygroups(Operator, using(this), Operator)),
            (r'(<-\[)(.*?)(\]-)', bygroups(Operator, using(this), Operator)),
            (r'(-\[)(.*?)(\]-)', bygroups(Operator, using(this), Operator)),
            (r'-->|<--|\[|\]', Operator),
            (r'<|>|<>|=|<=|=>|\(|\)|\||:|,|;', Punctuation),
            (r'[.*{}]', Punctuation),
        ],
        'strings': [
            (r'"(?:\\[tbnrf\'"\\]|[^\\"])*"', String),
            (r'`(?:``|[^`])+`', Name.Variable),
        ],
        'whitespace': [
            (r'\s+', Whitespace),
        ],
        'barewords': [
            (r'[a-z]\w*', Name),
            (r'\d+', Number),
        ],
    }
