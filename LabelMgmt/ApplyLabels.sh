#!/bin/bash

# Author : Siggi Bjarnason
# Copyright (c) Nanitor.com
# Assumes Bash Linux shell. Windows is slightly different.

export DELIM=";"
export DELIM2=","
export APIBASEURL="https://demo.nanitor.com/"
export APIKEY="SystemAPIKey"
export LOGLEVEL=10
python3 ApplyLabels2Assets.py infile.csv