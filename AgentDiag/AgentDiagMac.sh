#!/bin/bash

# Author : Siggi Bjarnason
# Copyright (c) Nanitor.com

if [[ -n $1 ]]
then
  OrgName=$1
else
  echo "Please specify a name for your org: "
  read OrgName
fi

if [[ -z $OrgName ]] 
then 
  echo "Need a name for your org for the file name, any string that identifies the owner of this machine"
  exit 5
fi
hostname=$(hostname)
LogFileName="agentDebug-$OrgName-$hostname.txt"
echo "Output will be saved to $LogFileName"
BasePath="/Library/Nanitor/Nanitor Agent/"
curdir=$(pwd)
echo "Save currend directory as $curdir"
binName="nanitor-agent-bin"
basever=$("$BasePath$binName" -v)
[[ $basever =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]
basever=${BASH_REMATCH[1]}
echo "Base version in $BasePath is $basever"
latest=$basever

cd "${BasePath}"

export NANITOR_TEST_CLI=1
echo "--------- Agent Version -------" > "${curdir}/${LogFileName}"
./$binName -v >> "${curdir}/${LogFileName}" 2>&1
testonce=$(./$binName test_once 2>&1)
urlPattern="Server URL: (.*)/api"
[[ $testonce =~ $urlPattern ]]
ServerURL=${BASH_REMATCH[1]}
echo "Testing connection to $ServerURL"
echo "--------- Test Connection to $ServerURL -------" >> "${curdir}/${LogFileName}"
ConnTest=$(curl $ServerURL 2>&1)
echo ${ConnTest:0:500} >> "${curdir}/${LogFileName}"
echo "Upgrade Maintenance"
echo "--------- Upgrade Maintenance -------" >> "${curdir}/${LogFileName}"
./$binName run_upgrade_maintenance >> "${curdir}/${LogFileName}" 2>&1
echo "Grabbing System Info"
echo "--------- System Info -------" >> "${curdir}/${LogFileName}"
./$binName test_system_info >> "${curdir}/${LogFileName}" 2>&1
echo "Grabbing Software info"
echo "--------- Software info -------" >> "${curdir}/${LogFileName}"
./$binName test_software_info >> "${curdir}/${LogFileName}" 2>&1
echo "Grabbing Patch Info"
echo "--------- Patch info -------" >> "${curdir}/${LogFileName}"
./$binName test_patch_info >> "${curdir}/${LogFileName}" 2>&1
echo "Posting to NanHelper"
curl -F file=@$LogFileName https://hub.nanitor.com/helper/file
cd "$curdir"