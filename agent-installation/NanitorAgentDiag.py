'''
Script that finds the latest nanitor agent on a machine
and executes a series of test commands to collect diagnostic data

Author Siggi Bjarnason SEP 2022
Nanitor Copyright 2022

'''
# Import libraries
import os
import sys
import subprocess
import platform
from packaging import version

def getInput(strPrompt):
    if sys.version_info[0] > 2 :
        return input(strPrompt)
    else:
        print("please upgrade to python 3.6 or greater")
        sys.exit()

def CollectInfo(strHeader,strOption):
  print(strHeader)
  objOutFile.write("\n--------- {} -------\n".format(strHeader))
  objOutput = subprocess.run([strAgentBin, strOption], stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE)
  strOutput = objOutput.stderr.decode("utf-8").strip()
  strOutput += objOutput.stdout.decode("utf-8").strip()
  objOutFile.write(strOutput+"\n")

if sys.version_info[0] < 3 :
  print("Sorry this only works in python 3.6 or greater ")
  sys.exit()

lstSysArg = sys.argv
iSysArgLen = len(lstSysArg)

if iSysArgLen > 1:
  strOrgName = lstSysArg[1]
  print("Welcome {} organization".format(strOrgName))
else:
  strOrgName = getInput("Please provide organization name or abriviation to identify your organization: ")
strScriptHost = platform.node().upper()

strWinPath = "c:/Program Files/Nanitor/Nanitor Agent/"
strLinuxPath = "/usr/lib/nanitor-agent/bin/"
strPlatform = sys.platform
if strPlatform[:3].lower() == "win":
  strBasePath = strWinPath
else:
  strBasePath = strLinuxPath
strAgentBin = strBasePath + "nanitor-agent-bin"
objOutput = subprocess.run([strAgentBin, "-v"], stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE)
strLines = objOutput.stdout.decode("utf-8").strip()
strParts = strLines.split()
strBaseVer = strParts[2]
print("The Agent in base directory is version {}".format(strBaseVer))
objDirectory = os.scandir(strBasePath)
strSuffix = ""
for objDirEntry in objDirectory:
  if objDirEntry.name == "versions":
    strSuffix = objDirEntry.name

strVersion = strBaseVer
strLocation = "base"
if strSuffix == "":
  strPath = strBasePath
else:
  strVerBasePath = strBasePath + "versions/"
  objDirectory = os.scandir(strVerBasePath)
  for objDirEntry in objDirectory:
    if (version.parse(strVersion) < version.parse(objDirEntry.name)):
      strVersion = objDirEntry.name
      strLocation = "version"

if strLocation == "base":
  strPath = strBasePath
else:
  strPath = strBasePath + "versions/" + strVersion +"/"

strOutPath = "{}agentDebug-{}-{}.txt".format(strPath,strOrgName,strScriptHost)
strAgentBin = strPath + "nanitor-agent-bin"
print("Latest version found was {} found at {}".format(strVersion,strPath))
print("Output will be saved to {}".format(strOutPath)) 
objOutFile = open(strOutPath,"w",encoding="utf8")
objOutFile.write("Debug information for {} on host {}\n".format(strOrgName,strScriptHost))
os.environ["NANITOR_TEST_CLI"] = "1"
objOutput = subprocess.run([strAgentBin, "test_once"], stdout=subprocess.PIPE, 
              stderr=subprocess.PIPE)
strOutput = objOutput.stderr.decode("utf-8").strip()
strOutput += objOutput.stdout.decode("utf-8").strip()
lstLines = strOutput.splitlines()
strURL = ""
for strline in lstLines:
  if "Server URL:" in strline:
    iStart = strline.find("Server URL:")
    iStart += 12
    iStop = strline.find("/",iStart+9)
    strURL = strline[iStart:iStop]

print ("Performing a connection test to {}".format(strURL))
objOutput = subprocess.run(["curl", strURL], stdout=subprocess.PIPE, 
              stderr=subprocess.PIPE)
strOutput = objOutput.stderr.decode("utf-8").strip()
strOutput += objOutput.stdout.decode("utf-8").strip()
objOutFile.write("--------- Test Connection to {} -------\n".format(strURL))
objOutFile.write(strOutput[:500]+"\n")
CollectInfo("Test Checkin","test_checkin_system_info")
CollectInfo("System Info","test_system_info")
CollectInfo("Software Info","test_software_info")
CollectInfo("Patch Info","test_patch_info")
subprocess.run(["curl","-F","file=@"+strOutPath,"https://hub.nanitor.com/helper/file"])