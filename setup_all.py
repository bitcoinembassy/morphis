# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

from distutils.core import setup
from Cython.Build import cythonize

setup(
    name = 'n1',
    ext_modules = cythonize(["*.py", "maalstroom/*.py"])
)
