from distutils.core import setup
from Cython.Build import cythonize

modules = [\
    "asymkey",
    "bittrie",
    "chord_packet",
    "enc",
    "llog",
    "mbase32",
    "mutil",
    "putil",
    "packet",
    "rsakey",
    "sshtype",
    "zbase32"\
]

setup(
    name = 'n1',
    ext_modules = cythonize(\
        [x + ".py" for x in modules])
)
