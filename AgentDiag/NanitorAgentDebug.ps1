param(
    [Parameter(Mandatory)][String]$org
    )
    
$cwd = Get-Location
$Hostname = hostname
$BasePath = "c:\Program Files\Nanitor\Nanitor Agent\"
Set-Location $BasePath
$strBaseVersion = .\nanitor-agent-bin.exe -v
if ($strBaseVersion -match "nanitor-agent-bin.exe version (?<ver>.*)")
{
  $Version = $matches["ver"]
  $Loc = "base"
}
else 
{
  $Version = "0.0.0.0"
  $Loc = ""
}
$strDirs = get-childitem -path $BasePath -attributes Directory `
| Select-Object Name | Format-Table -HideTableHeaders | Out-String
$dirs = $strDirs.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
$suffix = ""
foreach ($line in $dirs)
{
  if (($line -replace "\s+","") -eq "versions")
  {
    $suffix = "versions"
  }
}
if ($suffix -eq "")
{
  $strPath = $BasePath
}
else 
{
  $verBasePath = "$BasePath$suffix\"
  $strDirs = get-childitem -path $verBasePath -attributes Directory `
  | Select-Object Name | Format-Table -HideTableHeaders | Out-String
  $dirs = $strDirs.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
  
  foreach ($line in $dirs) 
  {
    if ([system.version]$line -gt [system.version]$Version)
    {
      $Version = $line
      $Loc = "version"
    }
  }
  $Version = $Version -replace '\s+', ''
  if ($Loc -eq "base")
  {
    $strPath = $BasePath
  }
  else 
  {
    $strPath = "$verBasePath$Version\"
  }
}
Set-Location $strPath
$OutFile = "agentDebug-$org-$Hostname.txt"
$OutFileName = "$strPath$OutFile"
Write-Output "Latest installed agent is $Version, found in $strPath"
Write-Output "Result will be saved to $OutFileName" 
Write-Output "Debug information for $org on host $Hostname" *> $OutFileName
$env:NANITOR_TEST_CLI =1
Write-Output "Test Connection"
$ConnectTest = .\nanitor-agent-bin.exe test_once 2>&1 | out-string
$lines = $ConnectTest.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
foreach ($line in $lines)
{
  if ($line -match "Server URL: (?<uri>.*)/.*")
  {
    $testURL = $matches["uri"]
    Write-Output "--------- Test Connection to $testURL -------"  *>> $OutFileName
    Invoke-WebRequest $testURL *>> $OutFileName
  }
}
Write-Output "Test Checkin"
Write-Output "--------- Test Checkin -------"  *>> $OutFileName
.\nanitor-agent-bin.exe test_checkin_system_info  *>> $OutFileName
Write-Output "Upgrade Maintenance"
Write-Output "--------- Upgrade Maintenance -------"  *>> $OutFileName
.\nanitor-agent-bin.exe run_upgrade_maintenance *>> $OutFileName
Write-Output "System Info"
Write-Output "--------- System Info -------"  *>> $OutFileName
.\nanitor-agent-bin.exe test_system_info *>> $OutFileName
Write-Output "Software Info"
Write-Output "--------- Software Info -------"  *>> $OutFileName
.\nanitor-agent-bin.exe test_software_info *>> $OutFileName
Write-Output "Patch Info"
Write-Output "--------- Patch Info -------"  *>> $OutFileName
.\nanitor-agent-bin.exe test_patch_info *>> $OutFileName
Write-Output "Reg Query"
Write-Output "--------- Reg Query -------"  *>> $OutFileName
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate *>> $OutFileName
Write-Output "MS Updates"
Write-Output "--------- MS Updates -------"  *>> $OutFileName
$searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$updates = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates
$updates | Format-Table Title,MsrcSeverity *>> $OutFileName
Write-Output "SCCM Info"
Write-Output "--------- SCCM Info -------"  *>> $OutFileName
$updates = get-wmiobject CCM_SoftwareUpdate -namespace "ROOT\ccm\ClientSDK" *>> $OutFileName
$updates | Format-Table ArticleID, EvaluationState, ComplianceState *>> $OutFileName
Write-Output "Posting to Nanitor. If you get an error here please send your support contact the file $OutFileName"
$FileCont = Get-Content -raw -path $OutFileName
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"
$bodyLines = (
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"$OutFile`"",
    "Content-Type: application/octet-stream$LF",
    $FileCont,
    "--$boundary--$LF"
) -join $LF

$PostURL = "https://hub.nanitor.com/helper/file"
Invoke-RestMethod -Uri $PostURL -Method Post -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
Set-Location $cwd