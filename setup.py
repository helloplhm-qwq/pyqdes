from setuptools import setup, Extension
import pybind11

module = Extension(
    'qdes',
    sources=['main.cpp'],
    include_dirs=[pybind11.get_include(), pybind11.get_include(user=True)]
)

setup(
    name='qdes',
    version='1.0',
    description='QDES encryption/decryption module',
    ext_modules=[module],
)
