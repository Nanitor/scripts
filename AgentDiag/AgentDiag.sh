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
BasePath="/usr/lib/nanitor-agent/bin/"
curdir=$(pwd)
echo "Save currend directory as $curdir"
binName="nanitor-agent-bin"
basever=$("$BasePath$binName" -v)
[[ $basever =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]
basever=${BASH_REMATCH[1]}
echo "Base version in $BasePath is $basever"
latest=$basever
if [ -d ${BasePath}versions ]
then
  cd ${BasePath}versions
  arr=(*)
  arr+=($basever)
  latest=$(echo ${arr[@]} | tr " " "\n" | sort -t . -n -r | head -1)
  echo "latest: $latest"
fi
if [[ $latest = $basever ]]
then
  cd ${BasePath}
  echo "Using $BasePath"
else
  cd ${BasePath}versions/$latest
  echo "Using ${BasePath}versions/$latest"
fi

export NANITOR_TEST_CLI=1
testonce=$(./$binName test_once 2>&1)
urlPattern="Server URL: (.*)/api"
[[ $testonce =~ $urlPattern ]]
ServerURL=${BASH_REMATCH[1]}
echo "Testing connection to $ServerURL"
ConnTest=$(curl $ServerURL 2>&1)
echo "--------- Test Connection to $ServerURL -------" > $LogFileName
echo ${ConnTest:0:500} >> $LogFileName
echo "Upgrade Maintenance"
echo "--------- Upgrade Maintenance -------" >> $LogFileName
./$binName run_upgrade_maintenance >> $LogFileName 2>&1
echo "Grabbing System Info"
echo "--------- System Info -------" >> $LogFileName
./$binName test_system_info >> $LogFileName 2>&1
echo "Grabbing Software info"
echo "--------- Software info -------" >> $LogFileName
./$binName test_software_info >> $LogFileName 2>&1
echo "Grabbing Patch Info"
echo "--------- Patch info -------" >> $LogFileName
./$binName test_patch_info >> $LogFileName 2>&1
echo "Posting to NanHelper"
curl -F file=@$LogFileName https://hub.nanitor.com/helper/file
cd "$curdir"