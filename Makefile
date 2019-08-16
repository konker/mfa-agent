
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

run: dist
	$(ROOT_DIR)/dist/mfa-agent

dist: venv distdir $(ROOT_DIR)/dist/mfa-agent

$(ROOT_DIR)/dist/mfa-agent:
	. venv/bin/activate && \
	pex mfa-agent -D $(ROOT_DIR) -r $(ROOT_DIR)/requirements.txt -m mfa-agent.main -o $(ROOT_DIR)/dist/mfa-agent && \
	deactivate

distdir:
	mkdir -p dist

venv:
	python -m venv venv && \
	. venv/bin/activate && \
	pip install -r requirements.txt && \
	deactivate

clean:
	rm -rf venv dist mfa-agent/*.egg-info
