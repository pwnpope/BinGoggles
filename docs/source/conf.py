# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------

import os
import sys
import sphinx_rtd_theme
import sphinx_rtd_dark_mode  # ← Dark-mode extension

sys.path.insert(0, os.path.abspath("../../"))

project   = 'BinGoggles'
copyright = '2025, pwnpope'
author    = 'pwnpope'
release   = '0.0.2'

# -- General configuration ---------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',         # Core autodoc support
    'sphinx.ext.napoleon',        # Google‐style docstrings
    'sphinx.ext.viewcode',        # Link to highlighted source
    'sphinx.ext.intersphinx',     # Cross-project linking
    'sphinx.ext.todo',            # TODO directives
    'sphinx.ext.autosummary',     # Generate summary tables
    'sphinx_rtd_theme',           # Read-the-Docs base theme
    'sphinx_rtd_dark_mode',       # Dark-mode switcher
]

autosummary_generate = True
todo_include_todos = True

# Napoleon settings (Google‐style only)
napoleon_google_docstring  = True
napoleon_numpy_docstring   = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True

# Autodoc settings
autodoc_member_order     = 'bysource'
autodoc_default_options  = {
    'members': True,
    'undoc-members': False,
    'show-inheritance': True,
}

templates_path   = ['_templates']
exclude_patterns = []

intersphinx_mapping = {
    'python':     ('https://docs.python.org/3', None),
    'binaryninja':('https://api.binary.ninja/',   None),
}

# -- Options for HTML output -------------------------------------------------

html_theme = 'sphinx_rtd_theme'
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

html_theme_options = {
    # RTD defaults
    'collapse_navigation': False,
    'display_version':      True,
    'navigation_depth':     4,

    # Dark-mode specific (sphinx_rtd_dark_mode)
    'style_nav_header_background': '#2980B9',
}

# sphinx-rtd-dark-mode configuration
dark_mode_color_scheme = "native"  # use RTD’s built-in colors for light/dark

html_static_path = ['_static']
