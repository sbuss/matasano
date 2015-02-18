VENV_DIR?=.venv
VENV_ACTIVATE=$(VENV_DIR)/bin/activate
WITH_VENV=. $(VENV_ACTIVATE);

PACKAGE_NAME?=matasano

TEST_OUTPUT?=nosetests.xml
COVERAGE_OUTPUT?=coverage.xml
COVERAGE_HTML_DIR?=cover

.PHONY: venv setup clean teardown lint test

$(VENV_ACTIVATE): requirements.txt
	test -d $@ || virtualenv --python=python2.7 $(VENV_DIR)
	$(WITH_VENV) pip install -r requirements.txt
	touch $@

venv: $(VENV_ACTIVATE)

setup: venv

clean:
	python setup.py clean
	rm -rf *.egg-info
	rm -rf $(MAKE_FABULOUS_BUILD_DIR)
	rm -rf $(PYTHON_SDIST_DIR)
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg*/
	find $(PACKAGE_NAME) -type f -name '*.pyc' -delete

teardown:
	rm -rf $(VENV_DIR)

lint: venv
	$(WITH_VENV) flake8 $(PACKAGE_NAME)/

test: venv
	$(WITH_VENV) nosetests \
		--with-doctest --with-xunit --xunit-file=${TEST_OUTPUT}

coverage: venv
	${WITH_VENV} nosetests \
		--with-coverage \
		--cover-html \
		--cover-html-dir=${COVERAGE_HTML_DIR} \
		--cover-xml \
		--cover-xml-file=${COVERAGE_OUTPUT} \
		--cover-package=$(PACKAGE_NAME)
