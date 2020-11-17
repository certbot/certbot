#!/bin/bash

if [ $# -ne 1 ];  then
  echo "Usage: $(basename $0) project-name"
  exit 1
fi

PROJECT=$1

yes "n" | sphinx-quickstart --dot _ --project $PROJECT --author "Certbot Project" -v 0 --release 0 --language en --suffix .rst --master index --ext-autodoc --ext-intersphinx --ext-todo --ext-coverage --ext-viewcode --makefile --batchfile $PROJECT/docs

cd $PROJECT/docs
sed -i -e "s|\# import os|import os|" conf.py
sed -i -e "s|\# needs_sphinx = '1.0'|needs_sphinx = '1.0'|" conf.py
sed -i -e "s|intersphinx_mapping = {'https://docs.python.org/': None}|intersphinx_mapping = {\n    'python': ('https://docs.python.org/', None),\n    'acme': ('https://acme-python.readthedocs.org/en/latest/', None),\n    'certbot': ('https://certbot.eff.org/docs/', None),\n}|" conf.py
sed -i -e "s|html_theme = 'alabaster'|\n# https://docs.readthedocs.io/en/stable/faq.html#i-want-to-use-the-read-the-docs-theme-locally\n# on_rtd is whether we are on readthedocs.org\non_rtd = os.environ.get('READTHEDOCS', None) == 'True'\nif not on_rtd:  # only import and set the theme if we're building docs locally\n    import sphinx_rtd_theme\n    html_theme = 'sphinx_rtd_theme'\n    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]\n# otherwise, readthedocs.org uses their theme by default, so no need to specify it|" conf.py
sed -i -e "s|# Add any paths that contain templates here, relative to this directory.|autodoc_member_order = 'bysource'\nautodoc_default_flags = ['show-inheritance']\n\n# Add any paths that contain templates here, relative to this directory.|" conf.py
sed -i -e "s|# The name of the Pygments (syntax highlighting) style to use.|default_role = 'py:obj'\n\n# The name of the Pygments (syntax highlighting) style to use.|" conf.py
# If the --ext-todo flag is removed from sphinx-quickstart, the line below can be removed.
sed -i -e "s|todo_include_todos = True|todo_include_todos = False|" conf.py
echo "/_build/" >> .gitignore
echo "=================
API Documentation
=================

.. toctree::
   :glob:

   api/**" > api.rst
sed -i -e "s|   :caption: Contents:|   :caption: Contents:\n\n.. automodule:: ${PROJECT//-/_}\n   :members:\n\n.. toctree::\n   :maxdepth: 1\n\n   api|" index.rst

echo "Suggested next steps:
* Add API docs to: $PROJECT/docs/api/
* Run: git add $PROJECT/docs"
