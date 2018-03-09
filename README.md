# Antivirus Check Service

__Antivirus Check Service__ provides the ability to scan files against a local installed clamav daemon. Furthermore  this service provides an URL scan using [virustotal](https://www.virustotal.com).
The __Antivirus Check Service__ processes incoming scan requests and reports the scan result to a given webhook.

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
}
~~~

### AMQP
The __Antivirus Check Service__ provides an AMQP API as well (which is uses by the WebAPI as well). 
Authenticate and Publish a message to the regarding queue:

- url: `amqp://<user>:<password>@<antivirus-check-service>/%2fantivirus`

#### scan file:
 - routing key: `scan_file`
 - payload:
    ~~~json
    {
      "download_uri": "https://<uri-to-file>",
      "callback_uri": "https://<uri-to-report-endpoint>"
    }
    ~~~

#### scan file:
 - routing key: `scan_url`
 - payload:
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

`git clone` this repository to a modern debian (currently stretch). Change to the new
directory and run as `root`: `make install`. This will install all necessary
packages.

- Copy `/antivirus_service/config.template.yml` to `/antivirus_service/config.yml`
  and adjust the config file
- Add `auth_keys` to the webserver section, format: `<username>:<password>`
- The python setup routine installs the packages locally (the clone path) and
  creates a link to `/usr/local/bin/antivirus`
- The installation process installs __Antivirus Check Service__ as three systemd
  services (for webserver, scan_file and scan_url). 
  Control the service with: `systemctl status antivirus-<webserver|scanfile|scanurl>.service`
- Adjust the the configuration in `config.yml` and start the service with:
  `systemctl start antivirus-<webserver|scanfile|scanurl>.service`
- The logs can be read by `journalctl -f -u antivirus-<webserver|scanfile|scanurl>.service`

- __BE PATIENT!__ At the first run, freshclam has to download all signatures, which can take a 
  long while and prevent clamav-daemon from working (don't forget to restart clamav-daemon).

## Update
Change to install directory and run `make update`

## Development & Testing

This project can be developed and tested in a vagrant box. `debian/stretch64` is used as predefined image.
It is strongly recommended to use the vagrant-vbguest plugin: by `vagrant plugin install vagrant-vbguest`.
(The virtualbox guest additions provides synchronizing the sources)

The vagrant command `vagrant up` starts a virtual machine and provision __Antivirus Check Service__
within. At the end of the provision the __Antivirus Check Service__ service will
be started.