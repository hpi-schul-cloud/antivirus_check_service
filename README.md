# Antivirus Check Service

The __Antivirus Check Service__ provides the ability to scan files with a locally installed clamav daemon. In addition, the service offers a URL scan using [virustotal](https://www.virustotal.com).
The __Antivirus Check Service__ processes incoming scan requests and sends the scan result to a specified web hook.

## Usage
__Antivirus Check Service__ provides two interfaces.

### WebAPI
The WebAPI is the most common interface to use __Antivirus Check Service__.
All requests besides of the root resource `/` have to be authenticated using basic access authentication.

A GET request to `https://<antivirus-check-service>/` gives a detailed usage api doc:
~~~json
"scan file request": {
    "description": "Download file and scan against virus (using local clamd), report back to given webhook uri",
    "path": "/scan/file",
    "method": "POST",
    "params": {
        "download_uri": {
            "type": "string",
            "description": "Complete uri to the downloadable file"
        },
        "callback_uri": {
            "type": "string",
            "description": "Complete uri to the callback uri"
        },
    }
},
"scan url request": {
    "description": "Scan Url (using virustotal), report back to given webhook Uri",
    "path": "/scan/url",
    "method": "POST",
    "params": {
        "url": {
            "type": "string",
            "description": "Url to scan using virustotal"
        },
        "callback_uri": {
            "type": "string",
            "description": "Complete Uri to the callback uri"
        },
    }
},
"clamav daemon version": {
    "description": "Get clamav daemon version and last database update",
    "path": "/antivirus-version",
    "method": "GET"
},
~~~

To get the clamav daemon version and last database update, you can send a request to the WebAPI `/antivirus-version`.
The response is similar to:
~~~json
{"clamd-version": "0.99.2/24389/Tue", "clamd-database-version": "2018/03/13 - 08:12:22"}
~~~

### AMQP
The __Antivirus Check Service__ provides an AMQP API, which is uses by the WebAPI as well. 
Authenticate and publish a message to the regarding queue using the routing_key:

- url: `amqp://<user>:<password>@<antivirus-check-service>/antivirus`

#### scan file:
 - routing key: `scan_file`
 - message:
    ~~~json
    {
      "download_uri": "https://<uri-to-file>",
      "callback_uri": "https://<uri-to-report-endpoint>"
    }
    ~~~

#### scan file:
 - routing key: `scan_url`
 - message:
    ~~~json
    {
      "url": "https://<url-to-be-scanned>",
      "callback_uri": "https://<uri-to-report-endpoint>"
    }
    ~~~

### Reports
The reports are PUT requests to the given webhook Uri. The payload differs reagrding the scan type.

#### scan file payload
~~~json
{"virus_detected": "<true|false>", "virus_signature": "<null|signature name>"}
~~~

#### scan url payload
~~~json
{"blacklisted": "<true|false>", "full_report": "<virustotal's full report>"}
~~~


## Install
As prerequisite you have to have installed: `git` and `make`.

### Rabbitmq
It's not necessary to install rabbitmq locally, if there is a rabbitmq server on which the amqp vhost can be installed.

Install rabbitmq by running these steps:
```bash
# install all rabbitmq-server (amqp-tools are optional)
apt install -y rabbitmq-server amqp-tools

# enable rabbitmq cli tools
rabbitmq-plugins enable rabbitmq_management

# set rabbitmq user, vhost and queue
rabbitmqctl add_vhost antivirus
rabbitmqctl add_user antivirus <password>
rabbitmqctl set_permissions -p antivirus antivirus ".*" ".*" ".*"
rabbitmqctl set_user_tags antivirus administrator
rabbitmqadmin declare queue --vhost=antivirus name=scan_file durable=true -u antivirus -p <password>
rabbitmqadmin declare queue --vhost=antivirus name=scan_url durable=true -u antivirus -p <password>
```

### VirusTotal
An API-Key is needed to use virustotal. To get this, an account on virustotal has to be created. The API-Key can be found in the account's settings.

### Service
`git clone` this repository to a modern debian (currently stretch). Change to the new
directory and run as `root`: `make install`. This will install all necessary
packages.

- Copy `/antivirus_service/config.template.yml` to `/antivirus_service/config.yml`
  and adjust the config file.
  It is possible to connect to clamav daemon over network. For this, the clamd has to be configured:
  Append the config values to `/etc/clamav/clamd.conf`
  ```
  TCPSocket 3310
  TCPAddr 0.0.0.0
  ```
  **Attention!** By default the `StreamMaxLength` value is set to 25M. Bigger files will be not excepted.

- Add `auth_keys` to the webserver section, format: `<username>:<password>`
- The python setup routine installs the packages locally (the clone path) and
  creates a link to `/usr/local/bin/antivirus`
- The installation process installs __Antivirus Check Service__ as three systemd
  services (for webserver, scan_file and scan_url). 
- __BE PATIENT!__ At the first run, freshclam has to download all signatures, which can take a 
  while and prevent clamav-daemon from working (don't forget to restart clamav-daemon).
- Start the service with:
  `systemctl start antivirus-<webserver|scanfile|scanurl>.service`
- Control the service with: `systemctl status antivirus-<webserver|scanfile|scanurl>.service`
- The logs can be read with: `journalctl -f -u antivirus-<webserver|scanfile|scanurl>.service`

## Verify installation
- Change to the `antivirus_check_service/resources` and start the development webserver with:
  `python3 develop_webserver.py`. The minimal webserver simulates the fileserver and listens for the webhook.
- To initiate the scan request run: `curl -v -d@scan_virus_file_payload.json -u <username>:<password> http://<antivirus-check-service>:8080/scan/file`, 
  whereby `scan_virus_file_payload.json` has the payload:
  ```json
  {
    "download_uri": "http://localhost:7000/infectedfile",
    "callback_uri": "http://localhost:7000/report"
  }
  ```
- The develop webserver has to show an output like:
  ```
  ======== Running on http://0.0.0.0:7000 ========
  (Press CTRL+C to quit)
  --- Scan Request Result ---
  {"virus_detected": true, "virus_signature": "Eicar-Test-Signature"}
  ```

## Update
Change to install directory and run `make update`

## Development & Testing

This project can be developed and tested in a vagrant box. `debian/stretch64` is used as predefined image.
It is strongly recommended to use the vagrant-vbguest plugin: by `vagrant plugin install vagrant-vbguest`.
(The virtualbox guest additions provides synchronizing the sources)

The vagrant command `vagrant up` starts a virtual machine and provision __Antivirus Check Service__
within. At the end of the provision the __Antivirus Check Service__ service will
be started.