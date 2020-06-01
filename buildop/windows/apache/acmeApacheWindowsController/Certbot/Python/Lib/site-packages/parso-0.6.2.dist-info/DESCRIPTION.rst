###################################################################
parso - A Python Parser
###################################################################


.. image:: https://travis-ci.org/davidhalter/parso.svg?branch=master
    :target: https://travis-ci.org/davidhalter/parso
    :alt: Travis CI build status

.. image:: https://coveralls.io/repos/github/davidhalter/parso/badge.svg?branch=master
    :target: https://coveralls.io/github/davidhalter/parso?branch=master
    :alt: Coverage Status

.. image:: https://raw.githubusercontent.com/davidhalter/parso/master/docs/_static/logo_characters.png

Parso is a Python parser that supports error recovery and round-trip parsing
for different Python versions (in multiple Python versions). Parso is also able
to list multiple syntax errors in your python file.

Parso has been battle-tested by jedi_. It was pulled out of jedi to be useful
for other projects as well.

Parso consists of a small API to parse Python and analyse the syntax tree.

A simple example:

.. code-block:: python

    >>> import parso
    >>> module = parso.parse('hello + 1', version="3.6")
    >>> expr = module.children[0]
    >>> expr
    PythonNode(arith_expr, [<Name: hello@1,0>, <Operator: +>, <Number: 1>])
    >>> print(expr.get_code())
    hello + 1
    >>> name = expr.children[0]
    >>> name
    <Name: hello@1,0>
    >>> name.end_pos
    (1, 5)
    >>> expr.end_pos
    (1, 9)

To list multiple issues:

.. code-block:: python

    >>> grammar = parso.load_grammar()
    >>> module = grammar.parse('foo +\nbar\ncontinue')
    >>> error1, error2 = grammar.iter_errors(module)
    >>> error1.message
    'SyntaxError: invalid syntax'
    >>> error2.message
    "SyntaxError: 'continue' not properly in loop"

Resources
=========

- `Testing <https://parso.readthedocs.io/en/latest/docs/development.html#testing>`_
- `PyPI <https://pypi.python.org/pypi/parso>`_
- `Docs <https://parso.readthedocs.org/en/latest/>`_
- Uses `semantic versioning <https://semver.org/>`_

Installation
============

    pip install parso

Future
======

- There will be better support for refactoring and comments. Stay tuned.
- There's a WIP PEP8 validator. It's however not in a good shape, yet.

Known Issues
============

- `async`/`await` are already used as keywords in Python3.6.
- `from __future__ import print_function` is not ignored.


Acknowledgements
================

- Guido van Rossum (@gvanrossum) for creating the parser generator pgen2
  (originally used in lib2to3).
- `Salome Schneider <https://www.crepes-schnaegg.ch/cr%C3%AApes-schn%C3%A4gg/kunst-f%C3%BCrs-cr%C3%AApes-mobil/>`_
  for the extremely awesome parso logo.


.. _jedi: https://github.com/davidhalter/jedi


.. :changelog:

Changelog
---------

0.6.2 (2020-02-27)
++++++++++++++++++

- Bugfixes
- Add Grammar.refactor (might still be subject to change until 0.7.0)

0.6.1 (2020-02-03)
++++++++++++++++++

- Add ``parso.normalizer.Issue.end_pos`` to make it possible to know where an
  issue ends

0.6.0 (2020-01-26)
++++++++++++++++++

- Dropped Python 2.6/Python 3.3 support
- del_stmt names are now considered as a definition
  (for ``name.is_definition()``)
- Bugfixes

0.5.2 (2019-12-15)
++++++++++++++++++

- Add include_setitem to get_definition/is_definition and get_defined_names (#66)
- Fix named expression error listing (#89, #90)
- Fix some f-string tokenizer issues (#93)

0.5.1 (2019-07-13)
++++++++++++++++++

- Fix: Some unicode identifiers were not correctly tokenized
- Fix: Line continuations in f-strings are now working

0.5.0 (2019-06-20)
++++++++++++++++++

- **Breaking Change** comp_for is now called sync_comp_for for all Python
  versions to be compatible with the Python 3.8 Grammar
- Added .pyi stubs for a lot of the parso API
- Small FileIO changes

0.4.0 (2019-04-05)
++++++++++++++++++

- Python 3.8 support
- FileIO support, it's now possible to use abstract file IO, support is alpha

0.3.4 (2019-02-13)
+++++++++++++++++++

- Fix an f-string tokenizer error

0.3.3 (2019-02-06)
+++++++++++++++++++

- Fix async errors in the diff parser
- A fix in iter_errors
- This is a very small bugfix release

0.3.2 (2019-01-24)
+++++++++++++++++++

- 20+ bugfixes in the diff parser and 3 in the tokenizer
- A fuzzer for the diff parser, to give confidence that the diff parser is in a
  good shape.
- Some bugfixes for f-string

0.3.1 (2018-07-09)
+++++++++++++++++++

- Bugfixes in the diff parser and keyword-only arguments

0.3.0 (2018-06-30)
+++++++++++++++++++

- Rewrote the pgen2 parser generator.

0.2.1 (2018-05-21)
+++++++++++++++++++

- A bugfix for the diff parser.
- Grammar files can now be loaded from a specific path.

0.2.0 (2018-04-15)
+++++++++++++++++++

- f-strings are now parsed as a part of the normal Python grammar. This makes
  it way easier to deal with them.

0.1.1 (2017-11-05)
+++++++++++++++++++

- Fixed a few bugs in the caching layer
- Added support for Python 3.7

0.1.0 (2017-09-04)
+++++++++++++++++++

- Pulling the library out of Jedi. Some APIs will definitely change.


