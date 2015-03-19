from distutils.core import setup
from Cython.Build import cythonize

setup(
    name = 'n1',
    ext_modules = cythonize("*.py")
)
