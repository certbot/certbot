(* Apache HTTPD lens for Augeas

Authors:
  David Lutterkort <lutter@redhat.com>
  Francis Giraldeau <francis.giraldeau@usherbrooke.ca>
  Raphael Pinson <raphink@gmail.com>

About: Reference
  Online Apache configuration manual: https://httpd.apache.org/docs/trunk/

About: License
    This file is licensed under the LGPL v2+.

About: Lens Usage
  Sample usage of this lens in augtool

  Apache configuration is represented by two main structures, nested sections
  and directives. Sections are used as labels, while directives are kept as a
  value. Sections and directives can have positional arguments inside values
  of "arg" nodes. Arguments of sections must be the firsts child of the
  section node.

  This lens doesn't support automatic string quoting. Hence, the string must
  be quoted when containing a space.

  Create a new VirtualHost section with one directive:
  > clear /files/etc/apache2/sites-available/foo/VirtualHost
  > set /files/etc/apache2/sites-available/foo/VirtualHost/arg "172.16.0.1:80"
  > set /files/etc/apache2/sites-available/foo/VirtualHost/directive "ServerAdmin"
  > set /files/etc/apache2/sites-available/foo/VirtualHost/*[self::directive="ServerAdmin"]/arg "admin@example.com"

About: Configuration files
  This lens applies to files in /etc/httpd and /etc/apache2. See <filter>.

*)


module Httpd =

autoload xfm

(******************************************************************
 *                           Utilities lens
 *****************************************************************)
let dels (s:string)     = del s s

(* The continuation sequence that indicates that we should consider the
 * next line part of the current line *)
let cont = /\\\\\r?\n/

(* Whitespace within a line: space, tab, and the continuation sequence *)
let ws = /[ \t]/ | cont

(* Any possible character - '.' does not match \n *)
let any = /(.|\n)/

(* Any character preceded by a backslash *)
let esc_any = /\\\\(.|\n)/

(* Newline sequence - both for Unix and DOS newlines *)
let nl = /\r?\n/

(* Whitespace at the end of a line *)
let eol = del (ws* . nl) "\n"

(* deal with continuation lines *)
let sep_spc             = del ws+ " "
let sep_osp             = del ws* ""
let sep_eq              = del (ws* . "=" . ws*) "="

let nmtoken             = /[a-zA-Z:_][a-zA-Z0-9:_.-]*/
let word                = /[a-z][a-z0-9._-]*/i

(* A complete line that is either just whitespace or a comment that only
 * contains whitespace *)
let empty = [ del (ws* . /#?/ . ws* . nl) "\n" ]

let indent              = Util.indent

(* A comment that is not just whitespace. We define it in terms of the
 * things that are not allowed as part of such a comment:
 *   1) Starts with whitespace
 *   2) Ends with whitespace, a backslash or \r
 *   3) Unescaped newlines
 *)
let comment =
  let comment_start = del (ws* . "#" . ws* ) "# " in
  let unesc_eol = /[^\]?/ . nl in
  let w = /[^\t\n\r \\]/ in
  let r = /[\r\\]/ in
  let s = /[\t\r ]/ in
  (*
   * we'd like to write
   * let b = /\\\\/ in
   * let t = /[\t\n\r ]/ in
   * let x = b . (t? . (s|w)* ) in
   * but the definition of b depends on commit 244c0edd in 1.9.0 and
   * would make the lens unusable with versions before 1.9.0. So we write
   * x out which works in older versions, too
   *)
  let x = /\\\\[\t\n\r ]?[^\n\\]*/ in
  let line = ((r . s* . w|w|r) . (s|w)* . x*|(r.s* )?).w.(s*.w)* in
  [ label "#comment" . comment_start . store line . eol ]

(* borrowed from shellvars.aug *)
let char_arg_sec  = /([^\\ '"\t\r\n>]|[^ '"\t\r\n>]+[^\\ \t\r\n>])|\\\\"|\\\\'|\\\\ /
let char_arg_wl   = /([^\\ '"},\t\r\n]|[^ '"},\t\r\n]+[^\\ '"},\t\r\n])/

let dquot =
     let no_dquot = /[^"\\\r\n]/
  in /"/ . (no_dquot|esc_any)* . /"/
let dquot_msg =
     let no_dquot = /([^ \t"\\\r\n]|[^"\\\r\n]+[^ \t"\\\r\n])/
  in /"/ . (no_dquot|esc_any)* . no_dquot

let squot =
     let no_squot = /[^'\\\r\n]/
  in /'/ . (no_squot|esc_any)* . /'/
let comp = /[<>=]?=/

(******************************************************************
 *                            Attributes
 *****************************************************************)

(* The arguments for a directive come in two flavors: quoted with single or
 * double quotes, or bare. Bare arguments may not start with a single or
 * double quote; since we also treat "word lists" special, i.e. lists
 * enclosed in curly braces, bare arguments may not start with those,
 * either.
 *
 * Bare arguments may not contain unescaped spaces, but we allow escaping
 * with '\\'. Quoted arguments can contain anything, though the quote must
 * be escaped with '\\'.
 *)
let bare = /([^{"' \t\n\r]|\\\\.)([^ \t\n\r]|\\\\.)*[^ \t\n\r\\]|[^{"' \t\n\r\\]/

let arg_quoted = [ label "arg" . store (dquot|squot) ]
let arg_bare = [ label "arg" . store bare ]

(* message argument starts with " but ends at EOL *)
let arg_dir_msg = [ label "arg" . store dquot_msg ]
let arg_wl  = [ label "arg" . store (char_arg_wl+|dquot|squot) ]

(* comma-separated wordlist as permitted in the SSLRequire directive *)
let arg_wordlist =
     let wl_start = dels "{" in
     let wl_end   = dels "}" in
     let wl_sep   = del /[ \t]*,[ \t]*/ ", "
  in [ label "wordlist" . wl_start . arg_wl . (wl_sep . arg_wl)* . wl_end ]

let argv (l:lens) = l . (sep_spc . l)*

(* the arguments of a directive. We use this once we have parsed the name
 * of the directive, and the space right after it. When dir_args is used,
 * we also know that we have at least one argument. We need to be careful
 * with the spacing between arguments: quoted arguments and word lists do
 * not need to have space between them, but bare arguments do.
 *
 * Apache apparently is also happy if the last argument starts with a double
 * quote, but has no corresponding closing double quote, which is what
 * arg_dir_msg handles
 *)
let dir_args =
  let arg_nospc = arg_quoted|arg_wordlist in
  (arg_bare . sep_spc | arg_nospc . sep_osp)* . (arg_bare|arg_nospc|arg_dir_msg)

let directive =
  [ indent . label "directive" . store word .  (sep_spc . dir_args)? . eol ]

let arg_sec = [ label "arg" . store (char_arg_sec+|comp|dquot|squot) ]

let section (body:lens) =
    (* opt_eol includes empty lines *)
    let opt_eol = del /([ \t]*#?[ \t]*\r?\n)*/ "\n" in
    let inner = (sep_spc . argv arg_sec)? . sep_osp .
             dels ">" . opt_eol . ((body|comment) . (body|empty|comment)*)? .
             indent . dels "</" in
    let kword = key (word - /perl/i) in
    let dword = del (word - /perl/i) "a" in
        [ indent . dels "<" . square kword inner dword . del />[ \t\n\r]*/ ">\n" ]

let perl_section = [ indent . label "Perl" . del /<perl>/i "<Perl>"
                   . store /[^<]*/
                   . del /<\/perl>/i "</Perl>" . eol ]


let rec content = section (content|directive)
                | perl_section

let lns = (content|directive|comment|empty)*

let filter = (incl "/etc/apache2/apache2.conf") .
             (incl "/etc/apache2/httpd.conf") .
             (incl "/etc/apache2/ports.conf") .
             (incl "/etc/apache2/conf.d/*") .
             (incl "/etc/apache2/conf-available/*.conf") .
             (incl "/etc/apache2/mods-available/*") .
             (incl "/etc/apache2/sites-available/*") .
             (incl "/etc/apache2/vhosts.d/*.conf") .
             (incl "/etc/httpd/conf.d/*.conf") .
             (incl "/etc/httpd/httpd.conf") .
             (incl "/etc/httpd/conf/httpd.conf") .
             (incl "/etc/httpd/conf.modules.d/*.conf") .
             Util.stdexcl

let xfm = transform lns filter
