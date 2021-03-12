write-host "
    __  _____    _______   ________  ____  ___                     
   / / / /   |  / ____/ | / /  _/ / / /  |/  /                     
  / /_/ / /| | / /_  /  |/ // // / / / /|_/ /                      
 / __  / ___ |/ __/ / /|  // // /_/ / /  / /                       
/_/ /_/_/_ |_/_/   /_/_|_/___/\____/_/__/_/_          __           
   / ____/  ______  / /___  (_) /_   /_  __/__  _____/ /____  _____
  / __/ | |/_/ __ \/ / __ \/ / __/    / / / _ \/ ___/ __/ _ \/ ___/
 / /____>  </ /_/ / / /_/ / / /_     / / /  __(__  ) /_/  __/ /    
/_____/_/|_/ .___/_/\____/_/\__/    /_/  \___/____/\__/\___/_/     
          /_/                                                      "


md -Force c:\HAFNIUMIOC-$env:computername\ | Out-Null
md -Force c:\temp | Out-Null
cd c:\HAFNIUMIOC-$env:computername\

# in testing we see some older unpatched systems not able to download from github.  this allows older os's to download the yara scanner and rules

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ServerCertificateValidationCallback
{ public static void Ignore()
{ if(ServicePointManager.ServerCertificateValidationCallback ==null)
{ ServicePointManager.ServerCertificateValidationCallback += 
delegate
(
Object obj, 
X509Certificate certificate, 
X509Chain chain, 
SslPolicyErrors errors
)
{ return true;};
}}}
"@
Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

Write-host Downloading the tools we need...

Invoke-WebRequest "https://github.com/VirusTotal/yara/releases/download/v4.0.2/yara-v4.0.2-1347-win64.zip" -OutFile yara64.zip

Invoke-WebRequest "https://raw.githubusercontent.com/Stetson-Cyber-Group-Inc/Exchange_HAFNIUM_Scanner/main/HAFNIUM.yar" -OutFile HAFNIUM.yar

Write-Host Unzipping tools...

Expand-Archive yara64.zip -Force

Write-host "Testing computer for HAFNIUM IOC's..."

#Get-ChildItem -Recurse -filter *.* 'C:\Windows\system32\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}
#Get-ChildItem -Recurse -filter *.* 'C:\Windows\syswow64\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}
Get-ChildItem -Recurse -filter *.* 'C:\Windows\temp\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}
Get-ChildItem -Recurse -filter *.* 'C:\inetpub\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}
Get-ChildItem -Recurse -filter *.* $env:exchangeinstallpath 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}
Get-ChildItem -Recurse -filter *.* 'C:\Program Files (x86)\fireeye\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}
Get-ChildItem -Recurse -filter *.* 'C:\temp\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}
Get-ChildItem -Recurse -filter *.* 'C:\Exchange\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}
Get-ChildItem  -filter *.* 'C:\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}

if ((Get-Item 'Warnings.txt').length -gt 10) { start Warnings.txt }
