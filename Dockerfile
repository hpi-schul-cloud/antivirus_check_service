FROM python:3.11-alpine

ENV LC_ALL=C.UTF-8
ENV LANG C.UTF-8

WORKDIR /usr/src/app
COPY requirements.txt setup.py ./
RUN pip3 install .
COPY antivirus_service ./antivirus_service

RUN python3 ./setup.py develop

ENTRYPOINT ["/usr/local/bin/antivirus"]
