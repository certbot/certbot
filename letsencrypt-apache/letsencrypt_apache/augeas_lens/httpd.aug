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
let sep_spc    =  del /([ \t]+|[ \t]*\\\\\r?\n[ \t]*)/ " "

let sep_osp             = Sep.opt_space
let sep_eq              = del /[ \t]*=[ \t]*/ "="

let nmtoken             = /[a-zA-Z:_][a-zA-Z0-9:_.-]*/
let word                = /[a-zA-Z][a-zA-Z0-9._-]*/

let comment             = Util.comment
let eol                 = Util.doseol
let empty               = Util.empty_dos
let indent              = Util.indent

(* borrowed from shellvars.aug *)
let char_arg_dir  = /[^ '"\t\r\n]|\\\\"|\\\\'/
let char_arg_sec  = /[^ '"\t\r\n>]|\\\\"|\\\\'/
let dquot = /"([^"\\\r\n]|\\\\.)*"/
let squot = /'([^'\\\r\n]|\\\\.)*'/

(******************************************************************
 *                            Attributes
 *****************************************************************)

let arg_dir = [ label "arg" . store (char_arg_dir+|dquot|squot) ]
let arg_sec = [ label "arg" . store (char_arg_sec+|dquot|squot) ]

let argv (l:lens) = l . (sep_spc . l)*

let directive = [ indent . label "directive" . store word .
                  (sep_spc . argv arg_dir)? . eol ]

let section (body:lens) =
    let inner = (sep_spc . argv arg_sec)? . sep_osp .
             dels ">" . eol . body* . indent . dels "</" in
    let kword = key word in
    let dword = del word "a" in
        [ indent . dels "<" . square kword inner dword . del ">" ">" . eol ]

let rec content = section (content|directive|comment|empty)

let lns = (content|directive|comment|empty)*

let filter = (incl "/etc/apache2/apache2.conf") .
             (incl "/etc/apache2/httpd.conf") .
             (incl "/etc/apache2/ports.conf") .
             (incl "/etc/apache2/conf.d/*") .
             (incl "/etc/apache2/mods-available/*") .
             (incl "/etc/apache2/sites-available/*") .
             (incl "/etc/httpd/conf.d/*.conf") .
             (incl "/etc/httpd/httpd.conf") .
             (incl "/etc/httpd/conf/httpd.conf") .
             Util.stdexcl

let xfm = transform lns filter
