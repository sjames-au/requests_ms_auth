SHELL:=/bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PACKAGE_VERSION:=$(shell cat VERSION)
PACKAGE_DIR:="${ROOT_DIR}/requests-adal-auth"
TESTS_DIR:="${ROOT_DIR}/tests"

.PHONY: all build code-quality test push help

all: help

info:
	@echo "PACKAGE_VERSION=${PACKAGE_VERSION}"
	@echo "ROOT_DIR=${ROOT_DIR}"
	@echo "PACKAGE_DIR=${PACKAGE_DIR}"
	@echo "TESTS_DIR=${TESTS_DIR}"

build:
	@echo "Building"

code-quality:
	@echo "Code Quality"

test:
	@echo "Testing"

push:
	@echo "Pushing"

help:
	@echo "#############################################"
	@echo "# This is a conveneince Makefile for Latigo #"
	@echo "#############################################"
	@echo ""
	@echo " General targets:"
	@echo ""
	@echo " + make help             Show this help"
	@echo " + make code-quality     Run code quality tools"
	@echo " + make build            Build the package."
	@echo " + make tests            Run tests."
	@echo " + make push             Push the package to Pypi"


