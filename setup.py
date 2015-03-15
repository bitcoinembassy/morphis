from distutils.core import setup
from Cython.Build import cythonize

modules = [\
    "llog",
    "bittrie",
    "enc",
    "mutil",
    "putil",
    "packet",
    "sshtype",
    "asymkey",
    "rsakey"\
]

setup(
    name = 'n1',
    ext_modules = cythonize(\
        [x + ".py" for x in modules])
)
