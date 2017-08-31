#!/bin/bash

# helper for running locally with stunnel
# requires google-cloud-sdk-app-engine-python


finish() { kill $(cat /tmp/stunnel.pid); exit; }
trap finish EXIT
    
stunnel stunnel.conf &
dev_appserver.py --log_level debug app.yaml
