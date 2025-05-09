.. BinGoggles documentation master file, created by
   sphinx-quickstart on Fri May  9 01:42:55 2025.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

BinGoggles's Documentation
======================================

The Assumed Taint Analysis Engine

Using BinGoggles with `Hugsy Headless <https://github.com/hugsy/binja-headless>`_
---------------------------------------------------------------------------------


.. code-block:: python

	from bingoggles.bingoggles_types import *
	from os import abspath

	test_bin = "./test/binaries/bin/test_mlil_store"
	bg_init = BGInitRpyc(
		target_bin=abspath(test_bin),
		libraries=["/lib/x86_64-linux-gnu/libc.so.6"],
		host="127.0.0.1",
		port=18812,
	)

	bn, bv, libraries_mapped = bg_init.init()

	analysis = Analysis(
		binaryview=bv, binaryninja=bn, verbose=True, libraries_mapped=libraries_mapped
	)

	analysis.tainted_slice(
		target=TaintTarget(0x00401212, "rdi"),
		var_type=SlicingID.FunctionVar,
		output=OutputMode.Printed,
	)



.. toctree::
   :maxdepth: 2
   :caption: Contents:



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
