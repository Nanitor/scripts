'''
Script that reads in a csv of hostname to label name
and applies the right label to the right asset in Nanitor
Uses Doppler Secrets manager for configuration items
Can also be passed in as environment variables


Author Siggi Bjarnason Dec 2023
Nanitor Copyright 2023

Following packages need to be installed
pip install requests
pip install jason

'''
# Import libraries
import os
import csv
import time
import platform
import sys
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

# End imports

if sys.version_info[0] > 2:
    import urllib.parse as urlparse
    # The following line surpresses a warning that we aren't validating the HTTPS certificate
    requests.urllib3.disable_warnings()
else:
    import urllib as urlparse
    # The following line surpresses a warning that we aren't validating the HTTPS certificate
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Few globals
tLastCall = 0
iTotalSleep = 0
iLogLevel = 5  # How much logging should be done. Level 10 is debug level, 0 is none

# sub defs


def getInput(strPrompt):
    if sys.version_info[0] > 2:
        return input(strPrompt)
    else:
        return raw_input(strPrompt)


def CleanExit(strCause):
    """
    Handles cleaning things up before unexpected exit in case of an error.
    Things such as closing down open file handles, open database connections, etc.
    Logs any cause given, closes everything down then terminates the script.
    Remember to add things here that need to be cleaned up
    Parameters:
      Cause: simple string indicating cause of the termination, can be blank
    Returns:
      nothing as it terminates the script
    """
    if strCause != "":
        strMsg = "{} is exiting abnormally on {}: {}".format(
            strScriptName, strScriptHost, strCause)
        strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
        objLogOut.write("{0} : {1}\n".format(strTimeStamp, strMsg))
        print(strMsg)

    objLogOut.close()
    print("objLogOut closed")
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


def isFloat(fValue):
    """
    function to safely check if a value can be interpreded as a float
    Parameter:
      Value: A object to be evaluated
    Returns:
      Boolean indicating if the object is an float or not.
    """
    if isinstance(fValue, (float, int, str)):
        try:
            fTemp = float(fValue)
        except ValueError:
            fTemp = "NULL"
    else:
        fTemp = "NULL"
    return fTemp != "NULL"


def MakeAPICall(strURL, dictHeader, strMethod, dictPayload="", strUser="", strPWD=""):
    """
    Handles the actual communication with the API, has a backoff mechanism
    MinQuiet defines how many seconds must elapse between each API call.
    Sets a global variable iStatusCode, with the HTTP code returned by the API (200, 404, etc)
    Parameters:
      strURL: Simple String. API EndPoint to call
      dictHeader: Simple string with the header to pass along with the call
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

    # print("Header: {}".format(dictHeader))
    LogEntry("Doing a {} to URL: {}".format(strMethod, strURL), 5)
    try:
        if strMethod.lower() == "get":
            if strUser != "":
                LogEntry(
                    "I have none blank username so I'm doing basic username/password auth", 6)
                WebRequest = requests.get(strURL, timeout=iTimeOut, headers=dictHeader,
                                          auth=(strUser, strPWD), verify=False, proxies=dictProxies)
            else:
                LogEntry(
                    "username is blank, not attempting basic username/password auth", 6)
                WebRequest = requests.get(
                    strURL, timeout=iTimeOut, headers=dictHeader, verify=False, proxies=dictProxies)
            LogEntry("get executed", 6)
        if strMethod.lower() == "post":
            if dictPayload != "":
                LogEntry("with payload of: {}".format(dictPayload), 6)
                if strUser != "":
                    LogEntry(
                        "I have none blank username so I'm doing basic username/password auth", 6)
                    WebRequest = requests.post(strURL, json=dictPayload, timeout=iTimeOut,
                                               headers=dictHeader, auth=(strUser, strPWD), verify=False, proxies=dictProxies)
                else:
                    LogEntry(
                        "username is blank, not attempting basic username/password auth", 6)
                    WebRequest = requests.post(strURL, json=dictPayload, timeout=iTimeOut,
                                               headers=dictHeader, verify=False, proxies=dictProxies)
            else:
                LogEntry("with no payload", 6)
                WebRequest = requests.post(
                    strURL, headers=dictHeader, verify=False, proxies=dictProxies)
            LogEntry("post executed", 6)
    except Exception as err:
        dictReturn["condition"] = "Issue with API call"
        dictReturn["errormsg"] = err
        return ({"Success": False}, [dictReturn])

    if isinstance(WebRequest, requests.models.Response) == False:
        LogEntry("response is unknown type", 1)
        strErrCode = "ResponseErr"
        strErrText = "response is unknown type"

    LogEntry("call resulted in status code {}".format(
        WebRequest.status_code), 5)
    iStatusCode = int(WebRequest.status_code)
    if iStatusCode != 200:
        strErrCode = WebRequest.status_code
        strErrText = WebRequest.text

    if strErrCode != "":
        dictReturn["condition"] = "problem with your request"
        dictReturn["errcode"] = strErrCode
        dictReturn["errormsg"] = strErrText
        return ({"Success": False}, [dictReturn])
    else:
        try:
            return ({"Success": True}, WebRequest.json())
        except Exception as err:
            dictReturn["condition"] = "failure converting response to jason"
            dictReturn["errormsg"] = err
            dictReturn["errorDetail"] = "Here are the first 199 character of the response: {}".format(
                WebRequest.text[:199])
            return ({"Success": False}, [dictReturn])


def main():
    global objLogOut
    global strScriptName
    global strScriptHost
    global dictProxies
    global iMinQuiet
    global iTimeOut
    global iBatchSize
    global iLogLevel
    global iOrgNum

    # Define few Defaults
    iTimeOut = 180   # Max time in seconds to wait for network response
    iMinQuiet = 2    # Minimum time in seconds between API calls
    iBatchSize = 100  # Default API Batch size
    strDelim = ","   # Default delim character for CSV file
    strDelim2 = ","  # Default delim character for label field in the CSV file

    ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
    lstSysArg = sys.argv
    iSysArgLen = len(lstSysArg)

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

    if not os.path.exists(strLogDir):
        os.makedirs(strLogDir)
        print("\nPath '{0}' for log files didn't exists, so I create it!\n".format(
            strLogDir))

    strScriptName = os.path.basename(sys.argv[0])
    iLoc = strScriptName.rfind(".")
    strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
    strVersion = "{0}.{1}.{2}".format(
        sys.version_info[0], sys.version_info[1], sys.version_info[2])
    strScriptHost = platform.node().upper()

    print("This is a script to apply labels to assets based on an input csv file. "
          "This is running under Python Version {}".format(strVersion))
    print("Running from: {}".format(strRealPath))
    dtNow = time.asctime()
    print("The time now is {}".format(dtNow))
    print("Logs saved to {}".format(strLogFile))
    objLogOut = open(strLogFile, "w", 1, encoding='utf8')

    # fetching secrets and configuration items from environment
    if os.getenv("LOGLEVEL") != "" and os.getenv("LOGLEVEL") is not None:
        if isInt(os.getenv("LOGLEVEL")):
            iLogLevel = int(os.getenv("LOGLEVEL"))
            LogEntry("Loglevel set to {}".format(iLogLevel), 4)
        else:
            LogEntry(
                "Invalid LOGLEVEL, setting to defaults of {}".format(iLogLevel), 3)
    else:
        LogEntry("No LOGLEVEL, setting to defaults of {}".format(iLogLevel), 3)

    strTemp = os.getenv("DELIM")
    strTemp = str(strTemp or '')
    if len(strTemp) == 1:
        strDelim = strTemp
        LogEntry("DELIM '{}' found in enviroment".format(strDelim), 6)
    else:
        LogEntry(
            "'{}' is not a valid DELIM, setting to defaults of '{}'".format(strTemp, strDelim), 3)

    strTemp = os.getenv("DELIM2")
    strTemp = str(strTemp or '')
    if len(strTemp) == 1:
        strDelim2 = strTemp
        LogEntry("DELIM2 '{}' found in enviroment".format(strDelim2), 6)
    else:
        LogEntry(
            "'{}' is not a valid DELIM2, setting to defaults of '{}'".format(strTemp, strDelim2), 3)

    if os.getenv("APIBASEURL") != "" and os.getenv("APIBASEURL") is not None:
        strBaseURL = os.getenv("APIBASEURL")
    else:
        CleanExit("No Base URL provided")
    strBaseURL = strBaseURL.strip()
    if os.getenv("APIKEY") != "" and os.getenv("APIKEY") is not None:
        strAPIKey = os.getenv("APIKEY")
    else:
        CleanExit("No API key provided")

    if os.getenv("INFILE") != "" and os.getenv("INFILE") is not None:
        strCSVName = os.getenv("INFILE")
    else:
        strCSVName = ""

    if os.getenv("PROXY") != "" and os.getenv("PROXY") is not None:
        strProxy = os.getenv("PROXY")
        dictProxies = {}
        dictProxies["http"] = strProxy
        dictProxies["https"] = strProxy
        LogEntry("Proxy has been configured for {}".format(strProxy), 4)
    else:
        dictProxies = {}

    if strBaseURL[-1:] != "/":
        strBaseURL += "/"

    if os.getenv("BATCHSIZE") != "" and os.getenv("BATCHSIZE") is not None:
        if isInt(os.getenv("BATCHSIZE")):
            iBatchSize = int(os.getenv("BATCHSIZE"))
        else:
            LogEntry(
                "Invalid BatchSize, setting to defaults of {}".format(iBatchSize), 3)
    else:
        LogEntry("No BatchSize, setting to defaults of {}".format(iBatchSize), 3)

    if os.getenv("TIMEOUT") != "" and os.getenv("TIMEOUT") is not None:
        if isInt(os.getenv("TIMEOUT")):
            iTimeOut = int(os.getenv("TIMEOUT"))
        else:
            LogEntry(
                "Invalid timeout, setting to defaults of {}".format(iTimeOut), 3)
    else:
        LogEntry("no timeout, setting to defaults of {}".format(iTimeOut), 3)

    if os.getenv("MINQUIET") != "" and os.getenv("MINQUIET") is not None:
        if isInt(os.getenv("MINQUIET")):
            iMinQuiet = int(os.getenv("MINQUIET"))
        else:
            LogEntry(
                "Invalid MinQuiet, setting to defaults of {}".format(iMinQuiet), 3)
    else:
        LogEntry("no MinQuiet, setting to defaults of {}".format(iMinQuiet), 3)

    dictHeader = {}
    dictHeader["Content-type"] = "application/json"
    dictHeader["Accept"] = "application/json"
    dictHeader["Authorization"] = "Bearer " + strAPIKey

    if iSysArgLen > 1:
        strCSVName = lstSysArg[1]
        LogEntry("Processing input file named : {}".format(strCSVName), 4)
    else:
        if strCSVName == "":
            strCSVName = getInput(
                "Please provide full path and filename for the CSV file to be imported: ")
        else:
            LogEntry("Using CSV Filename {} from Env.".format(strCSVName), 4)

    if strCSVName == "":
        print("No filename provided unable to continue")
        sys.exit()

    strCSVName = strCSVName.replace("\\", "/")
    if "/" not in strCSVName:
        strCSVName = strBaseDir + strCSVName

    if os.path.isfile(strCSVName):
        print("OK found {}".format(strCSVName))
    else:
        print("Can't find CSV file {}".format(strCSVName))
        sys.exit(4)

    try:
        objCSVIn = open(strCSVName, "r", encoding='utf8')
    except PermissionError:
        LogEntry("unable to open input file {} for reading, "
                 "permission denied.".format(strCSVName), 1, True)
    except FileNotFoundError:
        LogEntry("unable to open input file {} for reading, "
                 "File not found".format(strCSVName), 1, True)
    lstInputs = []
    csvReader = csv.reader(objCSVIn, delimiter=strDelim)
    for lstRow in csvReader:
        lstInputs.append(lstRow)
    objCSVIn.close()

    # actual work happens here

    iInSize = len(lstInputs)
    LogEntry("Now looping through the input file and finding the ID of each host."
             " There are {} entries.".format(iInSize), 4)
    LogEntry(" * Deliminator is '{}' *".format(strDelim), 4)
    iCurr = 1
    for lstLineParts in lstInputs:
        LogEntry("Processing line {} of {}".format(iCurr, iInSize), 4)
        iCurr += 1
        if len(lstLineParts) < 2:
            LogEntry("Skipping invalid line {}".format(lstLineParts), 8)
            continue
        strTemp = lstLineParts[0].lower()
        if strTemp[:1] == '\ufeff':
            strTemp = strTemp[1:]

        if strTemp == "hostname":
            LogEntry("Skipping header", 6)
            continue
        strHostName = strTemp
        LogEntry("working on host {}".format(strHostName), 8)

        lstLabels = lstLineParts[1].split(strDelim2)

        strAPIFunction = "system_api/assets"
        strMethod = "get"
        dictParams = {}
        iIndex = 1
        dictParams["per_page"] = iBatchSize
        dictParams["page"] = iIndex
        dictParams["hostname_starts_with"] = strHostName
        dictParams["archived"] = False
        if isinstance(dictParams, dict) and len(dictParams) > 0:
            strListScans = urlparse.urlencode(dictParams)
            strURL = strBaseURL + strAPIFunction + "?" + strListScans
        else:
            strURL = strBaseURL + strAPIFunction
        APIResp = MakeAPICall(strURL, dictHeader, strMethod)
        if APIResp[0]["Success"] == False:
            LogEntry(APIResp, 1, True)
        APIResponse = APIResp[1]
        if "items" in APIResponse:
            if isinstance(APIResponse["items"], list):
                for dictItem in APIResponse["items"]:
                    if "id" in dictItem:
                        iAssetID = dictItem["id"]
                        LogEntry("HostID for {} is {}".format(
                            strHostName, iAssetID), 4)
                    else:
                        LogEntry("Can't find the device ID for {}".format(
                            strHostName), 3)
                        continue
            else:
                if APIResponse["items"] is None:
                    LogEntry("Nothing Found", 3)
                    continue
                LogEntry("items collection is not a list, it is a {}".format(
                    type(APIResponse["items"])), 3)
        else:
            LogEntry("No items collection", 3)
            continue

        LogEntry("And applying labels to this hosts", 4)
        dictPayload = {}
        dictPayload["assets"] = []
        dictAsset = {}
        dictAsset["asset_id"] = iAssetID
        dictAsset["label_action"] = "add"
        dictAsset["labels"] = lstLabels
        dictPayload["assets"].append(dictAsset)
        strAPIFunction = "system_api/assets/update"
        strMethod = "post"
        strURL = strBaseURL + strAPIFunction
        APIResp = MakeAPICall(strURL, dictHeader, strMethod, dictPayload)
        if APIResp[0]["Success"] == False:
            LogEntry(APIResp, 1, True)
        else:
            LogEntry(APIResp[1], 5)

    # Closing thing out
    LogEntry("Done!", 1)
    objLogOut.close()


if __name__ == '__main__':
    main()
