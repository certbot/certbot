**ConfigObj** is a simple but powerful config file reader and writer: an *ini
file round tripper*. Its main feature is that it is very easy to use, with a
straightforward programmer's interface and a simple syntax for config files.
It has lots of other features though :

* Nested sections (subsections), to any level
* List values
* Multiple line values
* Full Unicode support
* String interpolation (substitution)
* Integrated with a powerful validation system

    - including automatic type checking/conversion
    - and allowing default values
    - repeated sections

* All comments in the file are preserved
* The order of keys/sections is preserved
* Powerful ``unrepr`` mode for storing/retrieving Python data-types

| Release 5.0.6 improves error messages in certain edge cases
| Release 5.0.5 corrects a unicode-bug that still existed in writing files
| Release 5.0.4 corrects a unicode-bug that still existed in reading files after
| fixing lists of string in 5.0.3
| Release 5.0.3 corrects errors related to the incorrectly handling unicode
| encoding and writing out files
| Release 5.0.2 adds a specific error message when trying to install on
| Python versions older than 2.5
| Release 5.0.1 fixes a regression with unicode conversion not happening
| in certain cases PY2
| Release 5.0.0 updates the supported Python versions to 2.6, 2.7, 3.2, 3.3
| and is otherwise unchanged
| Release 4.7.2 fixes several bugs in 4.7.1
| Release 4.7.1 fixes a bug with the deprecated options keyword in
| 4.7.0.
| Release 4.7.0 improves performance adds features for validation and
| fixes some bugs.

