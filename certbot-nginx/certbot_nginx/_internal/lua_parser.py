#
# lua_parser.py
#
# A simple parser for the Lua language.
#
# Copyright 2020, Paul McGuire
#
# Modified by Dmitrii Matveev, 2021

"""
from https://www.lua.org/manual/5.1/manual.html#8
    chunk ::= {stat [';']} [laststat [';']]
    block ::= chunk
    stat ::=  varlist '=' explist |
         functioncall |
         do block end |
         while exp do block end |
         repeat block until exp |
         if exp then block {elseif exp then block} [else block] end |
         for Name '=' exp ',' exp [',' exp] do block end |
         for namelist in explist do block end |
         function funcname funcbody |
         local function Name funcbody |
         local namelist ['=' explist]
    laststat ::= return [explist] | break
    funcname ::= Name {'.' Name} [':' Name]
    varlist ::= var {',' var}
    var ::=  Name | prefixexp '[' exp ']' | prefixexp '.' Name
    namelist ::= Name {',' Name}
    explist ::= {exp ','} exp
    exp ::=  nil | false | true | Number | String | '...' | function |
         prefixexp | tableconstructor | exp binop exp | unop exp
    prefixexp ::= var | functioncall | '(' exp ')'
    functioncall ::=  prefixexp args | prefixexp ':' Name args
    args ::=  '(' [explist] ')' | tableconstructor | String
    function ::= function funcbody
    funcbody ::= '(' [parlist] ')' block end
    parlist ::= namelist [',' '...'] | '...'
    tableconstructor ::= '{' [fieldlist] '}'
    fieldlist ::= field {fieldsep field} [fieldsep]
    field ::= '[' exp ']' '=' exp | Name '=' exp | exp
    fieldsep ::= ',' | ';'
    binop ::= '+' | '-' | '*' | '/' | '^' | '%' | '..' |
         '<' | '<=' | '>' | '>=' | '==' | '~=' |
         and | or
    unop ::= '-' | not | '#'
operator precedence:
     or
     and
     <     >     <=    >=    ~=    ==
     |
     ~
     &
     <<    >>
     ..
     +     -
     *     /     //    %
     unary operators (not   #     -     ~)
     ^
"""
import pyparsing as pp

ppc = pp.pyparsing_common
pp.ParserElement.enablePackrat()

LBRACK, RBRACK, LBRACE, RBRACE, LPAR, RPAR, EQ, COMMA, SEMI, COLON = map(
    pp.Suppress, "[]{}()=,;:"
)
OPT_SEMI = pp.Optional(SEMI).suppress()
ELLIPSIS = pp.Literal("...")
keywords = {
    k.upper(): pp.Keyword(k)
    for k in """\
    return break do end while if then elseif else for in function local repeat until nil false true and or not
    """.split()
}
RETURN = pp.Keyword('return')
BREAK = pp.Keyword('break')
DO = pp.Keyword('do')
END = pp.Keyword('end')
WHILE = pp.Keyword('while')
IF = pp.Keyword('if')
LOCAL = pp.Keyword('local')
THEN = pp.Keyword('then')
ELSEIF = pp.Keyword('elseif')
ELSE = pp.Keyword('else')
FOR = pp.Keyword('for')
IN = pp.Keyword('in')
FUNCTION = pp.Keyword('function')
REPEAT = pp.Keyword('repeat')
UNTIL = pp.Keyword('until')
NIL = pp.Keyword('nil')
FALSE = pp.Keyword('false')
TRUE = pp.Keyword('true')
AND = pp.Keyword('and')
OR = pp.Keyword('or')
NOT = pp.Keyword('not')
NL = pp.LineEnd().suppress()
# vars().update(keywords)
any_keyword = pp.MatchFirst(keywords.values()).setName("<keyword>")

comment_intro = pp.Literal("--")
long_comment_intro = pp.Regex(r"--\[\[")
long_comment = pp.Regex(r"\s*--\[\[(?:[^\]]+|\s*--\[\[(?!/))]*--]]")
short_comment = ~long_comment_intro + comment_intro + pp.restOfLine
lua_comment = long_comment | short_comment

# must use negative lookahead to ensure we don't parse a keyword as an identifier
ident = ~any_keyword + ppc.identifier

name = pp.delimitedList(ident, delim=".", combine=True)

namelist = pp.delimitedList(name)
number = ppc.number

# does not parse levels
multiline_string = pp.QuotedString("[[", endQuoteChar="]]", multiline=True)
string = pp.QuotedString("'") | pp.QuotedString('"') | multiline_string

exp = pp.Forward()

#     explist1 ::= {exp ','} exp
explist1 = pp.delimitedList(exp)

stat = pp.Forward()

#    laststat ::= return [explist1]  |  break
laststat = pp.Group(RETURN + explist1) | BREAK

#    block ::= {stat [';']} [laststat[';']]
block = pp.OneOrMore(pp.Group(stat + OPT_SEMI)) + pp.Optional(laststat + OPT_SEMI) |\
     laststat + OPT_SEMI

#    field ::= '[' exp ']' '=' exp  |  Name '=' exp  |  exp
field = pp.Group(
    LBRACK + exp + RBRACK + EQ + pp.Group(exp) | name + EQ + pp.Group(exp) | exp
)

#    fieldsep ::= ','  |  ';'
fieldsep = COMMA | SEMI

#    fieldlist ::= field {fieldsep field} [fieldsep]
field_list = pp.delimitedList(field, delim=fieldsep) + pp.Optional(fieldsep)

#    tableconstructor ::= '{' [fieldlist] '}'
tableconstructor = pp.Group(LBRACE + pp.Optional(field_list) + RBRACE)

#    parlist1 ::= namelist [',' '...']  |  '...'
parlist = namelist + pp.Optional(COMMA) + pp.Optional(ELLIPSIS) | ELLIPSIS

#    funcname ::= Name {'.' Name} [':' Name]
funcname = pp.Group(name + COLON + name) | name

#    function ::= function funcbody
#    funcbody ::= '(' [parlist1] ')' block end
funcbody = pp.Group(LPAR + pp.Optional(parlist) + RPAR) + block + END
function = FUNCTION + funcbody

#    args ::=  '(' [explist1] ')'  |  tableconstructor  |  String
args = LPAR + pp.Optional(explist1) + RPAR | tableconstructor | string

# this portion of the spec is left-recursive, must break LR loop
#    varlist1 ::= var {',' var}
#    var ::=  Name  |  prefixexp '[' exp ']'  |  prefixexp '.' Name
#    prefixexp ::= var  |  functioncall  |  '(' exp ')'
#    functioncall ::=  prefixexp args  |  prefixexp ':' Name args

prefixexp = name | LPAR + exp + RPAR
functioncall = prefixexp + args | prefixexp + COLON + name + args
var = pp.Forward()
var_atom = functioncall | name | LPAR + exp + RPAR
index_ref = pp.Group(LBRACK + exp + RBRACK)
var <<= pp.delimitedList(pp.Group(var_atom + index_ref) | var_atom, delim=".")

varlist1 = pp.delimitedList(var)

# exp ::=  nil  |  false  |  true  |  Number  |  String  |  '...'  |
#              function  |  prefixexp  |  tableconstructor
exp_atom = (
    NIL
    | FALSE
    | TRUE
    | number
    | string
    | ELLIPSIS
    | functioncall
    | var  # prefixexp
    | tableconstructor
)

# precedence of operations from https://www.lua.org/manual/5.3/manual.html#3.4.8
exp <<= pp.infixNotation(
    exp_atom,
    [
        ("^", 2, pp.opAssoc.LEFT),
        (NOT | pp.oneOf("# - ~"), 1, pp.opAssoc.RIGHT),
        (pp.oneOf("* / // %"), 2, pp.opAssoc.LEFT),
        (pp.oneOf("+ -"), 2, pp.opAssoc.LEFT),
        ("..", 2, pp.opAssoc.LEFT),
        (pp.oneOf("<< >>"), 2, pp.opAssoc.LEFT),
        ("&", 2, pp.opAssoc.LEFT),
        ("~", 2, pp.opAssoc.LEFT),
        ("|", 2, pp.opAssoc.LEFT),
        (pp.oneOf("< > <= >= ~= =="), 2, pp.opAssoc.LEFT),
        (AND, 2, pp.opAssoc.LEFT),
        (OR, 2, pp.opAssoc.LEFT),
    ],
)

assignment_stat = pp.Optional(LOCAL) + varlist1 + EQ + explist1
func_call_stat = pp.Optional(LOCAL) + functioncall
do_stat = DO + block + END
while_stat = WHILE + exp + block + END
repeat_stat = REPEAT + block + UNTIL + exp
for_loop_stat = (
    FOR + name + EQ + exp + COMMA + exp + pp.Optional(COMMA + exp) + DO + block + END
)
for_seq_stat = FOR + namelist + IN + explist1 + DO + block + END
if_stat = (
    IF
    + exp
    + THEN
    + block
    + pp.ZeroOrMore(pp.Group(ELSEIF + exp + THEN + block))
    + pp.Optional(pp.Group(ELSE + block))
    + END
)
function_def = pp.Optional(LOCAL) + FUNCTION + funcname + funcbody

for var_name in """
        assignment_stat
        func_call_stat
        do_stat
        while_stat
        repeat_stat
        for_loop_stat
        for_seq_stat
        if_stat
        function_def
        """.split():
    vars()[var_name].setName(var_name)

#    stat ::=  varlist1 '=' explist1  |
#              functioncall  |
#              do block end  |
#              while exp do block end  |
#              repeat block until exp  |
#              if exp then block {elseif exp then block} [else block] end  |
#              for Name '=' exp ',' exp [',' exp] do block end  |
#              for namelist in explist1 do block end  |
#              function funcname funcbody  |
#              local function Name funcbody  |
#              local namelist ['=' explist1]
stat <<= pp.Group(
    assignment_stat
    | do_stat
    | while_stat
    | repeat_stat
    | for_loop_stat
    | for_seq_stat
    | func_call_stat
    | if_stat
    | function_def
)

lua_script = pp.ZeroOrMore(stat)

# ignore comments
lua_script.ignore(lua_comment)
# if __name__ == "__main__":

#     sample = r"""
#     function test(x)
#         local t = {foo=1, bar=2, arg=x}
#         n = 0
#         if t['foo'] then
#             n = n + 1
#         end
#         if 10 > 8 then
#             n = n + 2
#         end
#         if (10 > 8) then
#             n = n + 2
#         end
#     end
#     """

#     try:
#         result = lua_script.parseString(sample)
#         result.pprint()
#     except pp.ParseException as pe:
#         print(pe.explain())
