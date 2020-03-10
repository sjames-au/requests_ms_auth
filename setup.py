#!/usr/bin/env python

import os
from setuptools import setup, find_packages

import logging

logger = logging.getLogger(__name__)

setup_requirements = ["pytest-runner", "setuptools_scm"]


version = open("VERSION").read().strip()


def remove_comment(line, sep="#"):
    i = line.find(sep)
    if i >= 0:
        line = line[:i]
    return line.strip()


def read_requirements_file(fname: str):
    fn = os.path.join(os.path.dirname(os.path.abspath(__file__)), fname)
    print(f"Reading requirements from {fn}")
    lines = []
    with open(fn) as f:
        for r in f.readlines():
            r = r.strip()
            if len(r) < 1:
                continue
            r = remove_comment(r)
            if len(r) < 1:
                continue
            lines.append(r)
    return lines


setup(
    name="requests_ms_auth",
    version=version,
    packages=find_packages(exclude=["tests*"]),
    setup_requires=setup_requirements,
    license="AGPL-3.0",
    description="Python requests session for microsoft with support for oauth2, adal and msal",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    install_requires=read_requirements_file("requirements/requirements.in"),  # Allow flexible deps for install
    tests_require=read_requirements_file("requirements/test_requirements.txt"),  # Use rigid deps for testing
    test_suite="tests",
    python_requires=">=3.4.0",
    url="https://github.com/equinor/requests_ms_auth",
    download_url=f"https://github.com/equinor/requests_ms_auth/dist/requests_ms_auth-{version}.tar.gz",
    author="Lennart Rolland",
    author_email="lennartrolland@gmail.com",
    classifiers=[
        "Intended Audience :: Developers",
        "Topic :: Utilities",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
)
