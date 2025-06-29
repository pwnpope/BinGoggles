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
	from bingoggles.bg import Analysis

	test_bin_path = "/home/pope/dev/BinGoggles/test/binaries/bin/test_mlil_store"
	bg_init = BGInitRpyc(target_bin=test_bin_path)

	bv, libraries_mapped = bg_init.init()

	analysis = Analysis(
		binaryview=bv, verbose=True, libraries_mapped=libraries_mapped
	)

	analysis.tainted_slice(
		target=TaintTarget(0x08049258, "eax_7"),
		var_type=SlicingID.FunctionVar,
	)



.. toctree::
   :maxdepth: 2
   :caption: Modules

   bingoggles.auxiliary
   bingoggles.bingoggles_types
   bingoggles.modules
   bingoggles.bg
   bingoggles.function_registry



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
