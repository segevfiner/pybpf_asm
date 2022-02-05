from setuptools import find_packages
from skbuild import setup


setup(
    name="bpf_asm",
    version="0.1.0",
    packages=find_packages(),
    zip_safe=False,
)
