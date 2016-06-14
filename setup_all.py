# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import os

from distutils.core import setup
from Cython.Build import cythonize

files = []

def add_path(files, path):
    for entry in os.listdir(path):
        if entry.endswith(".py") and not entry.endswith("_nocython.py"):
            files.append(path + "/" + entry)

add_path(files, os.getcwd())
add_path(files, os.getcwd() + "/maalstroom/")

setup(
    name = 'n1',
    ext_modules = cythonize(files)
)
