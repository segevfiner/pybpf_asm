# pybpf_asm - Python BPF Assembler
# Copyright (C) 2022  Segev Finer
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import re
from setuptools import find_packages
from skbuild import setup


with open("bpf_asm/__init__.py", "r", encoding="utf-8") as f:
    version = re.search(r'(?m)^__version__ = "([a-zA-Z0-9.-]+)"', f.read()).group(1)

with open("README.rst", "r", encoding="utf-8") as f:
    long_description = f.read()


setup(
    name="bpf_asm",
    version=version,
    author="Segev Finer",
    author_email="segev208@gmail.com",
    description="Python BPF Assembler",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/segevfiner/pybpf_asm",
    project_urls={
        "Documentation": "https://segevfiner.github.io/pybpf_asm/",
        "Issue Tracker": "https://github.com/segevfiner/pybpf_asm/issues",
    },
    license="GPL-2.0-only",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    keywords="bpf",
    zip_safe=False,
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "pybpf_asm = bpf_asm.__main__:main"
        ],
    },
    python_requires='>=3.6',
    extras_require={
        "dev": [
            "flake8",
            "pytest",
            "sphinx==5.*"
        ],
    }
)
