SHELL:=/bin/bash

help:
	@echo
	@echo "  Welcome."
	@echo
	@echo "    Target            Description"
	@echo "    -------------------------------------------------------------------"
	@echo "    clean             Cleanup installation"
	@echo "    help              You're reading this"
	@echo "    install           Clean, install set up project"
	@echo "    update            Clean, set up project"
	@echo
	@echo "  Have fun!"
	@echo

pyclean:
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf ./*.egg
	rm -rf ./*.egg-info

clean: pyclean

install_packages:
	apt update
	apt install -y python3 python3-setuptools python3-pip clamav-daemon clamav-freshclam clamav-unofficial-sigs python3-yaml python3-pika python3-requests python3-click python3-mock python3-pyclamd python3-celery python3-aiohttp
	service clamav-daemon start

systemctl_install:
	useradd -r antivirus
	usermod -a -G antivirus clamav
	cp ./resources/antivirus-webserver.service /lib/systemd/system/antivirus-webserver.service
	cp ./resources/antivirus-scanfile.service /lib/systemd/system/antivirus-scanfile.service
	cp ./resources/antivirus-scanurl.service /lib/systemd/system/antivirus-scanurl.service
	systemctl daemon-reload
	systemctl enable antivirus-webserver
	systemctl enable antivirus-scanfile
	systemctl enable antivirus-scanurl

install_project:
	python3 ./setup.py develop

update: clean
	git pull origin master
	python3 ./setup.py develop

install: clean install_packages install_project systemctl_install
