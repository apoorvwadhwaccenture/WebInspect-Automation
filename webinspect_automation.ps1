#Written for Powershell 7
#Variables
$wiAPIurl = '52.28.115.201'
$sscURL = 'http://18.197.209.236:8080/ssc/'
$applicationVersionID = '6'
$sscToken = 'Y2Y1NjJlZGItMzI1Mi00NjExLWEzMmYtMmQ2MzQ4ZTMwZDZj'

$scanURL = 'http://zero.webappsecurity.com/'
$crawlAuditMode = 'CrawlandAudit'
$scanName = 'zero.webappsecurity'

#API Auth
$pwd = ConvertTo-SecureString "password1" -AsPlainText -Force
$cred = New-Object Management.Automation.PSCredential ('username1', $pwd)

#1. Run the scan
$body = '{
"settingsName": "Default",
"overrides": {
"scanName": "' + $scanName + '",
"startUrls": [
"' + $scanURL + '"
],
"crawlAuditMode": "' + $crawlAuditMode + '",
"startOption": "Url"
}'

$responseurl = 'http://' + $wiAPIurl + '/webinspect/scanner/scans'
$response = Invoke-RestMethod -AllowUnencryptedAuthentication -Credential $cred -Method POST -ContentType "application/json" -Body $body -uri $responseurl
 
#Store unique ScanId
$scanId = $response.ScanId
Write-Host -ForegroundColor Green ("Scan started succesfully with Scan Id: " + $scanId)
 
#2. Get the current Status of the Scan
$StatusUrl = 'http://' + $wiAPIurl + '/webinspect/scanner/scans/' + $scanId + '/log'
$ScanCompleted = "ScanCompleted"
$ScanStopped = "ScanStopped"
$ScanInterrupted = "ScanInterrupted"
 
#Wait until the ScanStatus changed to ScanCompleted, ScanStopped or ScanInterrupted
do{
    $status = Invoke-RestMethod -AllowUnencryptedAuthentication -Credential $cred -Method GET -ContentType "application/json" -uri "$StatusUrl"
    $ScanDate =  $status[$status.Length-1].Date
    $ScanMessage = $status[$status.Length-1].Message
    $ScanStatus =  $status[$status.Length-1].Type
    Write-Host ($ScanDate, $ScanMessage, $ScanStatus) -Separator " - "
    Start-Sleep -Seconds 20
}
while(($ScanStatus -ne $ScanCompleted) -and ($ScanStatus -ne $ScanStopped) -and ($ScanStatus -ne $ScanInterrupted))
 
if ($ScanStatus -eq $ScanCompleted){
    Write-Host -ForegroundColor Green ("Scan completed!") `n

    #3. Export the scan to the FPR format
    $fprurl = 'http://' + $wiAPIurl + '/webinspect/scanner/scans/' + $scanId + '.fpr '
    $path = $scanId + '.fpr'

    Write-Host ("Downloading the result file (fpr)...")
    Invoke-RestMethod -AllowUnencryptedAuthentication -Credential $cred -Method GET -OutFile $path -uri "$fprurl"
    Write-Host -ForegroundColor Green ("Result file (fpr) download done!") `n
 
    #4. Upload the Results to SSC
    $sscheaders = '@{
        "Authorization" = "FortifyToken '+ $sscToken + '"
        "ContentType" = "multipart/form-data"
        "accept" = "application/json"
    }'
    $sscheader_exp = Invoke-Expression $sscheaders
    $sscuploadurl = $sscURL + 'api/v1/projectVersions/' + $applicationVersionID + '/artifacts'

    Write-Host ("Starting Upload to SSC...")
    Invoke-RestMethod -uri $sscuploadurl -Method POST -Headers $sscheader_exp -Form @{file=(Get-Item $path)}
    Write-Host -ForegroundColor Green ("Finished! Scan Results are now availible in the Software Security Center!")
}
else {
    Write-Host -ForegroundColor Red ("Error occured after Scan was finished!")
}