# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

from distutils.core import setup
from Cython.Build import cythonize

modules = [\
    "asymkey",
    "bittrie",
    "brute",
    "chord_packet",
    "consts",
    "dhgroup14",
    "enc",
    "htmlsafe",
    "llog",
    "mbase32",
    "mutil",
    "putil",
    "packet",
    "rsakey",
    "sshtype"\
]

setup(
    name = 'n1',
    ext_modules = cythonize(\
        [x + ".py" for x in modules])
)
