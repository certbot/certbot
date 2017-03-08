(* Apache HTTPD lens for Augeas

Authors:
  David Lutterkort <lutter@redhat.com>
  Francis Giraldeau <francis.giraldeau@usherbrooke.ca>
  Raphael Pinson <raphink@gmail.com>

About: Reference
  Online Apache configuration manual: http://httpd.apache.org/docs/trunk/

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

(* deal with continuation lines *)
let sep_spc             = del /([ \t]+|[ \t]*\\\\\r?\n[ \t]*)+/ " "
let sep_osp             = del /([ \t]*|[ \t]*\\\\\r?\n[ \t]*)*/ ""
let sep_eq              = del /[ \t]*=[ \t]*/ "="

let nmtoken             = /[a-zA-Z:_][a-zA-Z0-9:_.-]*/
let word                = /[a-z][a-z0-9._-]*/i

let eol                 = Util.doseol
let empty               = Util.empty_dos
let indent              = Util.indent

let comment_val_re      = /([^ \t\r\n](.|\\\\\r?\n)*[^ \\\t\r\n]|[^ \t\r\n])/
let comment             = [ label "#comment" . del /[ \t]*#[ \t]*/ "# "
                          . store comment_val_re . eol ]

(* borrowed from shellvars.aug *)
let char_arg_dir  = /([^\\ '"{\t\r\n]|[^ '"{\t\r\n]+[^\\ \t\r\n])|\\\\"|\\\\'|\\\\ /
let char_arg_sec  = /([^\\ '"\t\r\n>]|[^ '"\t\r\n>]+[^\\ \t\r\n>])|\\\\"|\\\\'|\\\\ /
let char_arg_wl   = /([^\\ '"},\t\r\n]|[^ '"},\t\r\n]+[^\\ '"},\t\r\n])/

let cdot = /\\\\./
let cl = /\\\\\n/
let dquot =
     let no_dquot = /[^"\\\r\n]/
  in /"/ . (no_dquot|cdot|cl)* . /"/
let dquot_msg =
     let no_dquot = /([^ \t"\\\r\n]|[^"\\\r\n]+[^ \t"\\\r\n])/
  in /"/ . (no_dquot|cdot|cl)*
let squot =
     let no_squot = /[^'\\\r\n]/
  in /'/ . (no_squot|cdot|cl)* . /'/
let comp = /[<>=]?=/

(******************************************************************
 *                            Attributes
 *****************************************************************)

let arg_dir = [ label "arg" . store (char_arg_dir+|dquot|squot) ]
(* message argument starts with " but ends at EOL *)
let arg_dir_msg = [ label "arg" . store dquot_msg ]
let arg_sec = [ label "arg" . store (char_arg_sec+|comp|dquot|squot) ]
let arg_wl  = [ label "arg" . store (char_arg_wl+|dquot|squot) ]

(* comma-separated wordlist as permitted in the SSLRequire directive *)
let arg_wordlist =
     let wl_start = Util.del_str "{" in
     let wl_end   = Util.del_str "}" in
     let wl_sep   = del /[ \t]*,[ \t]*/ ", "
  in [ label "wordlist" . wl_start . arg_wl . (wl_sep . arg_wl)* . wl_end ]

let argv (l:lens) = l . (sep_spc . l)*

let directive =
    (* arg_dir_msg may be the last or only argument *)
     let dir_args = (argv (arg_dir|arg_wordlist) . (sep_spc . arg_dir_msg)?) | arg_dir_msg
  in [ indent . label "directive" . store word .  (sep_spc . dir_args)? . eol ]

let section (body:lens) =
    (* opt_eol includes empty lines *)
    let opt_eol = del /([ \t]*#?\r?\n)*/ "\n" in
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
             Util.stdexcl

let xfm = transform lns filter
