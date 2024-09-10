# Antivirus Check Service

The __Antivirus Check Service__ provides the ability to scan files with a locally installed clamav daemon.
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
 - routing key: `scan_file_v2`
 - message:
    ~~~json
    {
      "download_uri": "https://<uri-to-file>",
      "callback_uri": "https://<uri-to-report-endpoint>"
    }
    ~~~

### Reports
The reports are PUT requests to the given webhook Uri. The payload differs reagrding the scan type.

#### scan file payload
~~~json
{"virus_detected": "<true|false>", "virus_signature": "<null|signature name>"}
~~~

### Error
If an error occures the __Antivirus Check Service__ will try to send an error page (500) with the error message as json:
~~~json
{"error": "<error message>"}
~~~

## CONFIGURATION

The configurate is taken via env vars.


