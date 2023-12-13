# ApplyLabels2Assets.py

## Introduction

This is a script that will apply static labels to assets based on a CSV input file. The script relies on environment variables for all the control factors as well as secrets such as the API key.

We Doppler Secrets management system to manage all these secrets and other configuration items and inject them into environment variables at runtime.

## Input File Format

The script assumes the following format:

```
HostName;Label-List
dbnandmem-01;cloud,bogus
dbnanora-01;Test,dev
```

There has to be at least two columns, all column beyond the first two are ignored. Also the header can be anything or can be left out. If the first header is HostName, the script will know that line is a header and skip it and does not look beyond HostName, otherwise the line is processed as a real data line. The separator, aka delineator, is configurable. The label column supports multi labels. If you want to supply multiple values in label column they need use a different delineator.

## Requirements

The script is designed for Python 3.

It requires the following:

- pip install Jason
- pip install requests

It also needs to have a few environment variables for secrets and customization:

- DELIM how is the input file delineated? If comma then DELIM=, or semicolon DELIM=; etc.
- DELIM2 how is the label column delineated? If only one label per line, this one doesn't matter.
- APIBASEURL is for the base Nanitor URL, that is the URL you use to log into Nanitor. For example: `https://demo.nanitor.com/`
- APIKEY This is your API key, see [help article on Nanitor's API](https://help.nanitor.com/97-rest-api/) for how to obtain your API key
- INFILE  way to pass in the name of the CSV file. You can also pass it in an argument or be prompted for it
- LOGLEVEL [optional] Level of logs you want to see. 10 is debug, 1 only errors, 5 you get basic status about what is happening. Any number between 1 and 10 is valid and produces different level of logs. The default is 5.
- BATCHSIZE [optional] If you want to limit the number of labels you fetch to something other than the default 100
- PROXY [optional] in case you need to specify a proxy to go through
- TIMEOUT [optional] in case you want to change the communication timeouts, specify integer number of seconds
- MINQUIET [optional] number of seconds to wait between each API call, as some APIs block you if you send more than x calls per minute. Default is 2 seconds; min is 1 sec. Specify an integer number of seconds to wait between each call.

## Execute example

 `python3 ApplyLabels2Assets.py infile.csv`

Where infile.csv is the input file with the asset to label matching, if you specified that in the environment variable or want to be prompted for it you can leave that off.  If the input file is someplace else than the current directory just provide a full path. There is a shell script file that applies all the major env variables and executes the script.
