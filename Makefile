SHELL:=/bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PACKAGE_VERSION:=$(shell cat VERSION)
PACKAGE_DIR:="${ROOT_DIR}/requests_ms_auth"
TESTS_DIR:="${ROOT_DIR}/tests"
EXAMPLES_DIR:="${ROOT_DIR}/examples"

define twine_config
[distutils]
index-servers=pypi
[pypi]
username=__token__
password=${TWINE_TOKEN}
endef
export twine_config

.PHONY: all info require prep build code-quality black flake mypy test pack push help

all: help

info:
	@echo "PACKAGE_VERSION=${PACKAGE_VERSION}"
	@echo "ROOT_DIR=${ROOT_DIR}"
	@echo "PACKAGE_DIR=${PACKAGE_DIR}"
	@echo "TESTS_DIR=${TESTS_DIR}"
	@echo "EXAMPLES_DIR=${EXAMPLES_DIR}"

require:
	pip install --upgrade pip
	pip uninstall requests_ms_auth -y
	pip install --upgrade pip-tools
	cat requirements/requirements.in | sort -u > requirements/temp_requirements.in
	pip-compile --output-file=requirements/requirements.txt requirements/temp_requirements.in
	cat requirements/requirements.in, requirements/test_requirements.in | sort -u > requirements/temp_requirements.in
	pip-compile --output-file=requirements/test_requirements.txt requirements/temp_requirements.in
	[ ! -e requirements/temp_requirements.in ] || rm requirements/temp_requirements.in
	pip install -r requirements/requirements.txt
	pip install -r requirements/test_requirements.txt

prep:
	@echo "Prepare development environment"
	pip install --upgrade pip
	pip uninstall requests_ms_auth -y
	pip install --upgrade pip-tools wheel twine
	pip install -r requirements/test_requirements.in
	pip install -r requirements/requirements.in

build:
	@echo "Building"

black:
	@echo "Ensuring code quality with black"
	black .

flake:
	@echo "Ensuring code quality with flake"
	flake8 "${PACKAGE_DIR}"

mypy:
	@echo "Ensuring code quality with mypy"
	mypy "${PACKAGE_DIR}"
	mypy "${TESTS_DIR}"
	# mypy "${EXAMPLES_DIR}" # TODO fix this

setup:
	rm -rf requests_ms_auth/build
	pip uninstall -y requests_ms_auth
	pip install -e .

code-quality: black flake mypy

test:
	@echo "Testing"
	python -m pytest --cov=requests_ms_auth -vv ${TESTS_DIR}

pack:
	@echo "Packaging"
	python setup.py sdist bdist_wheel
	ls -halt dist/

push:
	@echo "Pushing"
	echo "$$twine_config" > 'twine.conf'
	twine upload --config-file twine.conf dist/*.tar.gz --skip-existing --verbose
	rm 'twine.conf'

help:
	@echo ""
	@echo " Targets:"
	@echo ""
	@echo " + make help             Show this help"
	@echo " + make info             Show environment info"
	@echo " + make require          Update requirements pinning"
	@echo " + make prep             Prepare development environment"
	@echo " + make setup            Install local verion of package"
	@echo " + make code-quality     Run code quality tools"
	@echo " + make build            Build the package."
	@echo " + make test             Run tests."
	@echo " + make pack             Package the build into a PyPi package"
	@echo " + make push             Push the package to PyPi"
	@echo ""
