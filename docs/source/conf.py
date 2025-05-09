# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import sys
import sphinx_rtd_theme


sys.path.insert(0, os.path.abspath("../../"))

project = 'BinGoggles'
copyright = '2025, pwnpope'
author = 'pwnpope'
release = '0.0.2'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',       # core autodoc support
    'sphinx.ext.napoleon',      # to parse Google‐style docstrings
    'sphinx.ext.viewcode',      # add links to highlighted source
    'sphinx.ext.intersphinx',   # link to other projects’ docs
    'sphinx.ext.todo',          # support for TODO directives
    'sphinx.ext.autosummary',   # generate summary tables
    'sphinx_rtd_theme',         # custom theme
]
autosummary_generate = True
todo_include_todos = True

# Napoleon settings (Google‐style only)
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True

# Autodoc settings
autodoc_member_order = 'bysource'
autodoc_default_options = {
    'members': True,
    'undoc-members': False,
    'show-inheritance': True,
}

templates_path = ['_templates']
exclude_patterns = []

intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'binaryninja': ('https://api.binary.ninja/', None),
}

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'

html_theme_options = {
    'collapse_navigation': False,
    'display_version': True,
    'navigation_depth': 4,
}

html_static_path = ['_static']