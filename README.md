# hauditor

## Overview

hauditor is a tool designed to analyze the security headers returned by a web page and report dangerous configurations.


![hauditor Image](https://github.com/trap-bytes/hauditor/blob/main/static/hauditor.png)

## Features

- **Security Header Evaluation:** Examines the presence and values of identified security headers.
- **Overall Configuration Analysis:** Performs a comprehensive evaluation of the headers before flagging potentially risky configurations.
- **Content-Security-Policy Directive Analysis:** Analyzes CSP directives with a focus on configurations that may allow XSS attacks.
- **WAF Bypass:** Makes basic adjustments to the request to avoid potential blocking by WAFs.
- **Multiple Target Analysis:** It is possible to analyze security headers across multiple pages and domains.
  - *Example Use Case:* To assess all HTTP security headers for a given domain being analyzed via BurpSuite, right-click on the domain in Burp's SiteMap section, select "Copy URLs in this host," save them in a text file, and feed it to hauditor via the `-f` flag.

## Install

```
go install github.com/trap-bytes/hauditor@latest
```
## Usage:

```
hauditor -h
```

This will display help for the tool. Here are all the arguments it supports.

```
Usage:
  hauditor [arguments]

The arguments are:
  -t string    Specify the target URL (e.g., domain.com or https://domain.com)
  -f string    Specify the file (e.g., domain.txt)
  -m string    HTTP method (HEAD, GET, POST, PUT, etc.)
  -b string    HTTP request body
  -p string    Specify the proxy URL (e.g., 127.0.0.1:8080)
  -c string    Specify cookies (e.g., "user_token=g3p21ip21h;"
  -r string    Specify headers (e.g., "Myheader: test")
  -timeout     Timeout for HTTP requests in seconds
  -j           Output in JSON format
  -h           Display help

Examples:
  ./hauditor -t domain.com
  ./hauditor -t https://domain.com -p 127.0.0.1:8080
  ./hauditor -f domains.txt
  ./hauditor -c "user_token=hjljkklpo"
  ./hauditor -r "Myheader: test"
```
