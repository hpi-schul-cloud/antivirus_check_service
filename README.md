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
The __Antivirus Check Service__ provides an AMQP API, which is used by the WebAPI as well. 
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

#### scan url:
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

### Error
If an error occures the __Antivirus Check Service__ will try to send an error page (500) with the error message as json:
~~~json
{"error": "<error message>"}
~~~

## Install

Create the folder `./secrets`. 
- Copy `./resources/config.template.yml` to `./secrets/config.yml`
  Adjust the values in `< ... >`, this are username, passwords and other credentials.
  Follow the step below to get the `<virustotal-api-key>`.

- Copy `./resources/rabbitmq-definitions.template.json` to `./secrets/rabbitmq-definitions.json`.
  Adjust the amqp `<user>` and the `<sha256-hash-of-users-password>`.
  To get the `<sha256-hash-of-users-password>` you can follow the (missleading) documentation from rabbitmq:
  https://www.rabbitmq.com/passwords.html#computing-password-hash .
  
  Or you can use my tool. Change to `./resources` and run `python encrypt_rabbitmq_password.py --password="<your-rabbit-password>"` (only python2). 

### VirusTotal
An API-Key is needed to use virustotal. To get this, an account on virustotal has to be created. The API-Key can be found in the account's settings.

### Docker-Compose
- To start all services, you only have to to run `docker-compose up -d`
  This will start all docker container:
  - clamav
  - rabbitmq
  - webserver
  - scanfile
  - scanurl
  The last three container will restart until rabbitmq is running properly (ca. 10 seconds)

- __BE PATIENT!__ At the first run, freshclam has to download all signatures, which can take a 
  while and prevent clamav-daemon from working.
