PYTHON = python3
APP    = $(PYTHON) -m cyborg_shield.main

.PHONY: install test demo reset help

install:
	pip install -r requirements.txt

test:
	$(PYTHON) -m pytest tests/ -v

demo: reset
	@echo "\n--- Chargement du profil web-server ---"
	$(APP) preset web-server
	@echo "\n--- Simulation 10 paquets (40% attaques) ---"
	$(APP) simulate -n 10 -r 0.4
	@echo "\n--- Test d'un paquet SSH suspect ---"
	$(APP) test-packet -s 192.168.99.1 -P 22 -p tcp

reset:
	rm -f config/rules.json

help:
	$(APP) --help
