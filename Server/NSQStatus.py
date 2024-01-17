import os
import json
import subprocess
import time
import sys

strLogFile = "/root/NSQLog.csv"
objLogOut = open(strLogFile, "a")

os.environ["NANITOR_TEST_CLI"] = "1"
objOutput = subprocess.run(["/usr/lib/nanitor-server/bin/nanitor-cli", "nsq_status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
                           )
strErr = objOutput.stderr.decode("utf-8").strip()
if strErr != "":
    print(strErr)
    sys.exit()
strOutput = objOutput.stdout.decode("utf-8").strip()
lstLine = strOutput.splitlines()
del lstLine[0]
del lstLine[-5:]
strLines = "\n".join(lstLine)
dictLines = json.loads(strLines)
lstHeader = ["Date/Time"]
strNow = time.strftime("%Y-%m-%d %H:%M:%S %Z")
lstData = [strNow]
for dictTopics in dictLines["topics"]:
    lstHeader.append(dictTopics["topic_name"])
    lstData.append(str(dictTopics["channels"][0]["depth"]))
strHeader = ";".join(lstHeader)
strData = ";".join(lstData)
if os.path.getsize(strLogFile) > 0:
    strLineOut = strData + "\n"
else:
    strLineOut = "{}\n{}\n".format(strHeader, strData)
objLogOut.write(strLineOut)
