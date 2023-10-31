'''
Script that exports all the issues from your Nanitor instance
Uses Doppler Secrets manager for environment and secret management
See ExportIssue.env for environment variables.

Author Siggi Bjarnason 26 Oktober 2023
Nanitor Copyright 2023

Following packages need to be installed
pip install requests
pip install jason

'''
# Import libraries
import os
import time
import platform
import sys
import csv
import re
import yaml
import subprocess
try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'requests'])
finally:
    import requests
try:
    import json
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'json'])
finally:
    import json

if sys.version_info[0] > 2:
    import urllib.parse as urlparse
    # The following line surpresses a warning that we aren't validating the HTTPS certificate
    requests.urllib3.disable_warnings()
else:
    import urllib as urlparse
    # The following line surpresses a warning that we aren't validating the HTTPS certificate
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# End imports

# Few globals
tLastCall = 0
iTotalSleep = 0

# Define few Defaults
iLogLevel = 5     # How much logging should be done. Level 10 is debug level, 0 is none
iTimeOut = 45     # Max time in seconds to wait for network response
iMinQuiet = 2     # Minimum time in seconds between API calls
iBatchSize = 10   # Default API Batch size
strDelim = ";"    # Default delim character for CSV file
strDelim2 = ","   # Default delim character for 2nd level, i.e list within a line
strOutfile = "Issues.csv"
strFormat = "%Y-%m-%d %H:%M:%S"

# sub defs


def CleanExit(strCause):
    """
    Handles cleaning things up before unexpected exit in case of an error.
    Things such as closing down open file handles, open database connections, etc.
    Logs any cause given, closes everything down then terminates the script.
    Parameters:
      Cause: simple string indicating cause of the termination, can be blank
    Returns:
      nothing as it terminates the script
    """
    if strCause != "":
        LogEntry("{} is exiting abnormally on {}: {}".format(
            strScriptName, strScriptHost, strCause))

    objLogOut.close()
    print("objLogOut closed")
    if objFileOut is not None:
        objFileOut.close()
        print("objFileOut closed")
    else:
        print("objFileOut is not defined yet")
    sys.exit(9)


def LogEntry(strMsg, iMsgLevel, bAbort=False):
    """
    This handles writing all event logs into the appropriate log facilities
    This could be a simple text log file, a database connection, etc.
    Needs to be customized as needed
    Parameters:
      Message: Simple string with the event to be logged
      iMsgLevel: How detailed is this message, debug level or general. Will be matched against Loglevel
      Abort: Optional, defaults to false. A boolean to indicate if CleanExit should be called.
    Returns:
      Nothing
    """
    if iLogLevel > iMsgLevel:
        strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
        objLogOut.write("{0} : {1}\n".format(strTimeStamp, strMsg))
        print(strMsg)
    else:
        if bAbort:
            strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
            objLogOut.write("{0} : {1}\n".format(strTimeStamp, strMsg))

    if bAbort:
        CleanExit("")


def formatUnixDate(iDate):
    """
    A simple function to conver UNIX style epoc time to human readable format
    Parameter:
      iDate: An integer containing the epoc time
    Returns:
      string with that date formated per format directive.
    """
    structTime = time.localtime(iDate)
    return time.strftime(strFormat, structTime)


def isInt(CheckValue):
    """
    function to safely check if a value can be interpreded as an int
    Parameter:
      Value: A object to be evaluated
    Returns:
      Boolean indicating if the object is an integer or not.
    """
    if isinstance(CheckValue, (float, int, str)):
        try:
            fTemp = int(CheckValue)
        except ValueError:
            fTemp = "NULL"
    else:
        fTemp = "NULL"
    return fTemp != "NULL"


def MakeAPICall(strURL, strHeader, strMethod, dictPayload="", strUser="", strPWD=""):
    """
    Handles the actual communication with the API, has a backoff mechanism
    MinQuiet defines how many seconds must elapse between each API call.
    Sets a global variable iStatusCode, with the HTTP code returned by the API (200, 404, etc)
    Parameters:
      strURL: Simple String. API EndPoint to call
      strHeader: Simple string with the header to pass along with the call
      strMethod: Simple string. Call method such as GET, PUT, POST, etc
      Payload: Optional. Any payload to send along in the appropriate structure and format
      User: Optional. Simple string. Username to use in basic Auth
      Password: Simple string. Password to use in basic auth
    Return:
      Returns a tupple of single element dictionary with key of Success,
      plus a list with either error messages or list with either error messages
      or result of the query, list of dictionaries..
      ({"Success":True/False}, [dictReturn])
    """
    global tLastCall
    global iTotalSleep
    global iStatusCode

    fTemp = time.time()
    fDelta = fTemp - tLastCall
    LogEntry("It's been {} seconds since last API call".format(fDelta), 6)
    if fDelta > iMinQuiet:
        tLastCall = time.time()
    else:
        iDelta = int(fDelta)
        iAddWait = iMinQuiet - iDelta
        LogEntry("It has been less than {} seconds since last API call, "
                 "waiting {} seconds".format(iMinQuiet, iAddWait), 6)
        iTotalSleep += iAddWait
        time.sleep(iAddWait)

    strErrCode = ""
    strErrText = ""
    dictReturn = {}

    LogEntry("Doing a {} to URL: {}".format(strMethod, strURL), 5)
    try:
        if strMethod.lower() == "get":
            if strUser != "":
                LogEntry(
                    "I have none blank credentials so I'm doing basic auth", 6)
                WebRequest = requests.get(strURL, timeout=iTimeOut, headers=strHeader,
                                          auth=(strUser, strPWD), verify=False)
            else:
                LogEntry("credentials are blank, proceeding without auth", 6)
                WebRequest = requests.get(
                    strURL, timeout=iTimeOut, headers=strHeader, verify=False)
                LogEntry("get executed", 6)
        if strMethod.lower() == "post":
            if dictPayload != "":
                LogEntry("with payload of: {}".format(dictPayload), 6)
                WebRequest = requests.post(strURL, json=dictPayload, timeout=iTimeOut,
                                           headers=strHeader, auth=(strUser, strPWD), verify=False)
            else:
                WebRequest = requests.post(
                    strURL, headers=strHeader, verify=False)
            LogEntry("post executed", 6)
    except Exception as err:
        dictReturn["condition"] = "Issue with API call"
        dictReturn["errormsg"] = err
        return ({"Success": False}, [dictReturn])

    if isinstance(WebRequest, requests.models.Response) == False:
        LogEntry("response is unknown type", 2)
        strErrCode = "ResponseErr"
        strErrText = "response is unknown type"

    LogEntry("call resulted in status code {}".format(
        WebRequest.status_code), 5)
    iStatusCode = int(WebRequest.status_code)

    if strErrCode != "":
        dictReturn["condition"] = "problem with your request"
        dictReturn["errcode"] = strErrCode
        dictReturn["errormsg"] = strErrText
        return ({"Success": False}, [dictReturn])

    try:
        dictResponse = WebRequest.json()
    except Exception as err:
        dictReturn["condition"] = "failure converting response to jason"
        dictReturn["errormsg"] = err
        dictReturn["errorDetail"] = "Here are the first 199 character of the response: {}".format(
            WebRequest.text[:199])
        return ({"Success": False}, [dictReturn])

    if "success" in dictResponse:
        return ({"Success": dictResponse["success"]}, dictResponse)
    else:
        return ({"Success": True}, dictResponse)


def OpenFile(strFileName, strperm, strNewLine=""):
    """
    Handles creating a file handle in a safe manner with error handling and such.
    Parameters:
      strFileName: What is the full path of the file to open
      strperm: Should the be open for read, write, append or binary operations
      strNewLine: Any newline character, defaults to blank.
    Returns:
      object handle to the opened file, or an error string
    """

    if sys.version_info[0] > 2:
        try:
            objFileOut = open(strFileName, strperm,
                              encoding='utf8', newline=strNewLine)
            return objFileOut
        except PermissionError:
            LogEntry("unable to open output file {} for writing, "
                     "permission denied.".format(strFileName), 1, True)
            return ("Permission denied")
        except FileNotFoundError:
            LogEntry("unable to open output file {} for writing, "
                     "Issue with the path".format(strFileName), 1, True)
            return ("file not found")
    else:
        try:
            objFileOut = open(strFileName, strperm)
            return objFileOut
        except IOError as err:
            LogEntry("unable to open output file {} for writing, {}".format(
                strFileName, err))
            return ("File open failure")


def ImpactedHosts(strAPIFunction, iID, strHeader, strMethod):
    """
    Handles fetching impacted hosts for a specific issue number
    Parameters:
      strAPIFunction: what is the function to query for impacted hosts
      iID: What is the issue ID
      strHeader: API Header with things such as auth
      strMethod: Is the API call a get, post, etc.
    Returns:
      list object of all hosts impacted along with their IPs, or an error string
    """

    lstReturn = []
    strURL = strBaseURL + strAPIFunction + "/" + str(iID)
    APIResp = MakeAPICall(strURL, strHeader, strMethod)
    if APIResp[0]["Success"] == False:
        LogEntry(APIResp, 1, True)
    APIResponse = APIResp[1]
    if "item" in APIResponse:
        if "affected_devices" in APIResponse["item"]:
            if isinstance(APIResponse["item"]["affected_devices"], list):
                for dictItem in APIResponse["item"]["affected_devices"]:
                    if "hostname" in dictItem:
                        strHostname = dictItem["hostname"]
                    else:
                        strHostname = "n/a"
                    if "ip_addresses" in dictItem:
                        lstIPaddr = dictItem["ip_addresses"]
                    else:
                        lstIPaddr = ["n/a"]
                    strHost = "{} {}".format(strHostname, lstIPaddr)
                    lstReturn.append(strHost)
            else:
                return "no list"
            return lstReturn
        else:
            return "None"
    else:
        return "not found"


def LoadConfig(strConfigPath):
    """
    function to load in a yaml file with configuration items
    Parameter:
      yaml_path: full path of the file to load
    Returns:
      Dictionary with data from the YAML or error message
    """
    try:
        if os.path.isfile(strConfigPath):
            with open(strConfigPath, "r") as f:
                device_info = yaml.safe_load(f)
            return device_info
        else:
            return "YAML path {} doesn't exist".format(strConfigPath)
    except Exception as err:
        return "failed to load yaml {}. {}".format(strConfigPath, err)


def GetConfItem(strItemName):
    """
    Fetches a particular configuration item, either from environment variable
    or configuration dictionary loaded by LoadConfig.
    Parameters:
      strItemName: Name of the configuration item. This should match the env variable name
    Returns:
      string value of the variable
    """
    if os.getenv(strItemName) != "" and os.getenv(strItemName) is not None:
        return os.getenv(strItemName)
    else:
        if strItemName in dictConfig:
            return dictConfig[strItemName]
        else:
            return ""


def main():
    global strFileOut
    global objFileOut
    global objLogOut
    global strScriptName
    global strScriptHost
    global strBaseDir
    global strBaseURL
    global iMinQuiet
    global iTimeOut
    global strDelim
    global iBatchSize
    global strOutDir
    global strOutfile
    global strDelim
    global strDelim2
    global dictConfig
    global strFormat

    ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
    strFileOut = None

    strBaseDir = os.path.dirname(sys.argv[0])
    strRealPath = os.path.realpath(sys.argv[0])
    strRealPath = strRealPath.replace("\\", "/")
    if strBaseDir == "":
        iLoc = strRealPath.rfind("/")
        strBaseDir = strRealPath[:iLoc]
    if strBaseDir[-1:] != "/":
        strBaseDir += "/"
    strLogDir = strBaseDir + "Logs/"
    if strLogDir[-1:] != "/":
        strLogDir += "/"
    strOutDir = strBaseDir + "out/"

    if not os.path.exists(strLogDir):
        os.makedirs(strLogDir)
        print("\nPath '{0}' for log files didn't exists, so I create it!\n".format(
            strLogDir))

    strScriptName = os.path.basename(sys.argv[0])
    iLoc = strScriptName.rfind(".")
    strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
    strConfPath = strBaseDir + strScriptName[:iLoc] + ".yml"
    strVersion = "{0}.{1}.{2}".format(
        sys.version_info[0], sys.version_info[1], sys.version_info[2])
    strScriptHost = platform.node().upper()

    print("This is a script to download your Nanitor issue list. "
          "This is running under Python Version {}".format(strVersion))
    print("Running from: {}".format(strRealPath))
    dtNow = time.asctime()
    print("The time now is {}".format(dtNow))
    print("Logs saved to {}".format(strLogFile))
    objLogOut = open(strLogFile, "w", 1)
    objFileOut = None
    dictConfig = LoadConfig(strConfPath)
    if isinstance(dictConfig, str):
        LogEntry(dictConfig, 5)
        dictConfig = {}

    # fetching configuration variables
    strLabelFilter = GetConfItem("LABELS")
    strIssueTypeFilter = GetConfItem("ISSUETYPE")

    if GetConfItem("DATEFORMAT") != "":
        strFormat = GetConfItem("DATEFORMAT")

    if GetConfItem("DELIM") != "":
        strDelim = GetConfItem("DELIM")

    if GetConfItem("DELIM2") != "":
        strDelim2 = GetConfItem("DELIM2")

    if GetConfItem("APIBASEURL") != "":
        strBaseURL = GetConfItem("APIBASEURL")
    else:
        strBaseURL = input(
            "Please provide your instance login URL, such as https://mysite.nanitor.net\n")

    if GetConfItem("APIKEY") != "":
        strAPIKey = GetConfItem("APIKEY")
    else:
        strAPIKey = input("Please provide your API Key: ")

    if strBaseURL[-1:] != "/":
        strBaseURL += "/"

    if GetConfItem("OUTDIR") != "":
        strOutDir = GetConfItem("OUTDIR")
    else:
        LogEntry("No Outdir, set to default of: {}".format(strOutDir), 4)

    if GetConfItem("OUTFILE") != "":
        strOutfile = GetConfItem("OUTFILE")
    else:
        LogEntry("No Outfile, set to default of: {}".format(strOutfile), 4)

    if GetConfItem("BATCHSIZE") != "":
        if isInt(GetConfItem("BATCHSIZE")):
            iBatchSize = int(GetConfItem("BATCHSIZE"))
        else:
            LogEntry(
                "Invalid BatchSize, setting to defaults of {}".format(iBatchSize), 4)
    else:
        LogEntry("No BatchSize, setting to defaults of {}".format(iBatchSize), 4)

    if GetConfItem("TIMEOUT") != "":
        if isInt(GetConfItem("TIMEOUT")):
            iTimeOut = int(GetConfItem("TIMEOUT"))
        else:
            LogEntry(
                "Invalid timeout, setting to defaults of {}".format(iTimeOut), 4)
    else:
        LogEntry("no timeout, setting to defaults of {}".format(iTimeOut), 4)

    if GetConfItem("MINQUIET") != "":
        if isInt(GetConfItem("MINQUIET")):
            iMinQuiet = int(GetConfItem("MINQUIET"))
        else:
            LogEntry(
                "Invalid MinQuiet, setting to defaults of {}".format(iMinQuiet), 4)
    else:
        LogEntry("no MinQuiet, setting to defaults of {}".format(iMinQuiet), 4)

    strHeader = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'authorization': 'Bearer ' + strAPIKey
    }

    strOutDir = strOutDir.replace("\\", "/")
    if strOutDir[-1:] != "/":
        strOutDir += "/"

    if not os.path.exists(strOutDir):
        os.makedirs(strOutDir)
        LogEntry(
            "\nPath '{0}' for ouput files didn't exists, so I create it!\n".format(strOutDir), 5)

    strFileOut = strOutDir + strOutfile
    LogEntry("Output will be written to {}".format(strFileOut), 5)

    tmpResponse = OpenFile(strFileOut, "w")
    if isinstance(tmpResponse, str):
        CleanExit(tmpResponse)
    else:
        objFileOut = tmpResponse

    strRawOut = strOutDir + "RawOut.json"
    LogEntry("Raw Output will be written to {}".format(strRawOut), 5)

    tmpResponse = OpenFile(strRawOut, "w")
    if isinstance(tmpResponse, str):
        CleanExit(tmpResponse)
    else:
        objRawOut = tmpResponse

    # actual work happens here

    objCSVWrite = csv.writer(objFileOut, delimiter=strDelim)
    lstFilehead = ["ID", "Issue Type", "CVE", "Created Date/time", "Opened Date/time",
                   "Issue Title", "Resolved", "Excluded", "Impacted Hosts"]
    objCSVWrite.writerow(lstFilehead)

    strAPIFunction = "system_api/issues"
    strMethod = "get"
    dictParams = {}
    iIssueCount = 0
    iIndex = 1
    iTotalPages = 10
    if strIssueTypeFilter != "":
        dictParams["issue_type"] = strIssueTypeFilter
    if strLabelFilter != "":
        dictParams["label"] = strLabelFilter
    dictParams["excluded"] = "false"
    dictParams["per_page"] = iBatchSize
    while iIndex <= iTotalPages:
        dictParams["page"] = iIndex
        iIndex += 1
        if isinstance(dictParams, dict) and len(dictParams) > 0:
            strListScans = urlparse.urlencode(dictParams)
            strURL = strBaseURL + strAPIFunction + "?" + strListScans
        else:
            strURL = strBaseURL + strAPIFunction
        APIResp = MakeAPICall(strURL, strHeader, strMethod)
        if APIResp[0]["Success"] == False:
            CleanExit(APIResp)
        APIResponse = APIResp[1]
        objRawOut.write(json.dumps(APIResponse))
        if "page" in APIResponse:
            iPageNum = APIResponse["page"]
        else:
            LogEntry("No page number in response", 5)
            iPageNum = 0
        if "pages" in APIResponse:
            iTotalPages = APIResponse["pages"]
        else:
            LogEntry("No total pages number in response", 5)
            iTotalPages = 0
        if "total" in APIResponse:
            iTotalItems = APIResponse["total"]
        else:
            LogEntry("No total total number in response", 5)
            iTotalItems = 0
        LogEntry("On page #{} of {}.".format(
            iPageNum, iTotalPages, iTotalItems), 3)
        if "items" in APIResponse:
            if isinstance(APIResponse["items"], list):
                for dictItem in APIResponse["items"]:
                    iIssueCount += 1
                    if "id" in dictItem:
                        iID = dictItem["id"]
                        LogEntry(
                            "fetching impacted hosts for issue {}. Issue {} of {}".format(iID, iIssueCount, iTotalItems), 4)
                        strHostList = strDelim2.join(
                            ImpactedHosts(strAPIFunction=strAPIFunction, iID=iID, strHeader=strHeader, strMethod=strMethod))
                    else:
                        iID = 0
                    if "issue_type" in dictItem:
                        strIssueType = dictItem["issue_type"]
                    else:
                        strIssueType = "n/a"
                    if "created_at" in dictItem:
                        strCreatedTime = formatUnixDate(dictItem["created_at"])
                    else:
                        strCreatedTime = "n/a"
                    if "opened_at" in dictItem:
                        strOpenedTime = formatUnixDate(dictItem["opened_at"])
                    else:
                        strOpenedTime = "n/a"

                    if "title" in dictItem:
                        strIssueTitle = dictItem["title"]
                    else:
                        strIssueTitle = "n/a"
                    if "resolved" in dictItem:
                        bResolved = dictItem["resolved"]
                    else:
                        bResolved = None
                    if "excluded" in dictItem:
                        bExcluded = dictItem["excluded"]
                    else:
                        bExcluded = None
                    strIssueTitle = strIssueTitle.replace(strDelim, " ")
                    strIssueTitle = strIssueTitle.replace("\n", " ")
                    objRE = re.search(r"CVE-\d{4}-\d+", strIssueTitle)
                    if objRE is None:
                        strCVE = ""
                    else:
                        strCVE = objRE.group()
                    lstRowOut = [iID, strIssueType, strCVE, strCreatedTime, strOpenedTime,
                                 strIssueTitle, bResolved, bExcluded, strHostList]
                    objCSVWrite.writerow(lstRowOut)

    # Closing thing out

    if objFileOut is not None:
        objFileOut.close()
        LogEntry("objFileOut closed", 3)
    else:
        LogEntry("objFileOut is not defined yet", 3)

    LogEntry("Done! Output saved to {}".format(strFileOut), 2)
    objLogOut.close()


if __name__ == '__main__':
    main()
