from distutils.core import setup
from Cython.Build import cythonize

modules = [\
    "asymkey",
    "bittrie",
    "brute",
    "chord_packet",
    "dhgroup14",
    "enc",
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
