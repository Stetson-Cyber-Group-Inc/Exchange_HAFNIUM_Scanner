@ Echo OFF


color 0A

for /f "delims=: tokens=*" %%A in ('findstr /b ::::::::::: "%~f0"') do @echo(%%A

powershell "md -Force c:\HAFNIUMIOC-%computername%\ | Out-Null"
powershell "md -Force c:\temp | Out-Null"

cd c:\HAFNIUMIOC-%computername%\

echo.
echo Downloading the tools we need..
powershell -enc WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAAgAD0AIABbAE4AZQB0AC4AUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbABUAHkAcABlAF0AOgA6AFQAbABzADEAMgANAAoAaQBmACAAKAAtAG4AbwB0ACAAKABbAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBQAFMAVAB5AHAAZQBOAGEAbQBlAF0AJwBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAJwApAC4AVAB5AHAAZQApAA0ACgB7AA0ACgAkAGMAZQByAHQAQwBhAGwAbABiAGEAYwBrACAAPQAgAEAAIgANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0AOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBOAGUAdAA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAGMAdQByAGkAdAB5ADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AQwByAHkAcAB0AG8AZwByAGEAcABoAHkALgBYADUAMAA5AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBzADsADQAKAHAAdQBiAGwAaQBjACAAYwBsAGEAcwBzACAAUwBlAHIAdgBlAHIAQwBlAHIAdABpAGYAaQBjAGEAdABlAFYAYQBsAGkAZABhAHQAaQBvAG4AQwBhAGwAbABiAGEAYwBrAA0ACgB7ACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAHYAbwBpAGQAIABJAGcAbgBvAHIAZQAoACkADQAKAHsAIABpAGYAKABTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAC4AUwBlAHIAdgBlAHIAQwBlAHIAdABpAGYAaQBjAGEAdABlAFYAYQBsAGkAZABhAHQAaQBvAG4AQwBhAGwAbABiAGEAYwBrACAAPQA9AG4AdQBsAGwAKQANAAoAewAgAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIALgBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAIAArAD0AIAANAAoAZABlAGwAZQBnAGEAdABlAA0ACgAoAA0ACgBPAGIAagBlAGMAdAAgAG8AYgBqACwAIAANAAoAWAA1ADAAOQBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAGUAcgB0AGkAZgBpAGMAYQB0AGUALAAgAA0ACgBYADUAMAA5AEMAaABhAGkAbgAgAGMAaABhAGkAbgAsACAADQAKAFMAcwBsAFAAbwBsAGkAYwB5AEUAcgByAG8AcgBzACAAZQByAHIAbwByAHMADQAKACkADQAKAHsAIAByAGUAdAB1AHIAbgAgAHQAcgB1AGUAOwB9ADsADQAKAH0AfQB9AA0ACgAiAEAADQAKAEEAZABkAC0AVAB5AHAAZQAgACQAYwBlAHIAdABDAGEAbABsAGIAYQBjAGsADQAKACAAfQANAAoAWwBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAXQA6ADoASQBnAG4AbwByAGUAKAApAA0ACgBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIABoAHQAdABwAHMAOgAvAC8AcgBhAHcALgBnAGkAdABoAHUAYgB1AHMAZQByAGMAbwBuAHQAZQBuAHQALgBjAG8AbQAvAFMAdABlAHQAcwBvAG4ALQBDAHkAYgBlAHIALQBHAHIAbwB1AHAALQBJAG4AYwAvAEUAeABjAGgAYQBuAGcAZQBfAEgAQQBGAE4ASQBVAE0AXwBTAGMAYQBuAG4AZQByAC8AbQBhAGkAbgAvAEgAQQBGAE4ASQBVAE0ALgB5AGEAcgAgAC0ATwB1AHQARgBpAGwAZQAgAEgAQQBGAE4ASQBVAE0ALgB5AGEAcgA=

powershell -enc WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAAgAD0AIABbAE4AZQB0AC4AUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbABUAHkAcABlAF0AOgA6AFQAbABzADEAMgANAAoAaQBmACAAKAAtAG4AbwB0ACAAKABbAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBQAFMAVAB5AHAAZQBOAGEAbQBlAF0AJwBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAJwApAC4AVAB5AHAAZQApAA0ACgB7AA0ACgAkAGMAZQByAHQAQwBhAGwAbABiAGEAYwBrACAAPQAgAEAAIgANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0AOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBOAGUAdAA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAGMAdQByAGkAdAB5ADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AQwByAHkAcAB0AG8AZwByAGEAcABoAHkALgBYADUAMAA5AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBzADsADQAKAHAAdQBiAGwAaQBjACAAYwBsAGEAcwBzACAAUwBlAHIAdgBlAHIAQwBlAHIAdABpAGYAaQBjAGEAdABlAFYAYQBsAGkAZABhAHQAaQBvAG4AQwBhAGwAbABiAGEAYwBrAA0ACgB7ACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAHYAbwBpAGQAIABJAGcAbgBvAHIAZQAoACkADQAKAHsAIABpAGYAKABTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAC4AUwBlAHIAdgBlAHIAQwBlAHIAdABpAGYAaQBjAGEAdABlAFYAYQBsAGkAZABhAHQAaQBvAG4AQwBhAGwAbABiAGEAYwBrACAAPQA9AG4AdQBsAGwAKQANAAoAewAgAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIALgBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAIAArAD0AIAANAAoAZABlAGwAZQBnAGEAdABlAA0ACgAoAA0ACgBPAGIAagBlAGMAdAAgAG8AYgBqACwAIAANAAoAWAA1ADAAOQBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAGUAcgB0AGkAZgBpAGMAYQB0AGUALAAgAA0ACgBYADUAMAA5AEMAaABhAGkAbgAgAGMAaABhAGkAbgAsACAADQAKAFMAcwBsAFAAbwBsAGkAYwB5AEUAcgByAG8AcgBzACAAZQByAHIAbwByAHMADQAKACkADQAKAHsAIAByAGUAdAB1AHIAbgAgAHQAcgB1AGUAOwB9ADsADQAKAH0AfQB9AA0ACgAiAEAADQAKAEEAZABkAC0AVAB5AHAAZQAgACQAYwBlAHIAdABDAGEAbABsAGIAYQBjAGsADQAKACAAfQANAAoAWwBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAXQA6ADoASQBnAG4AbwByAGUAKAApAA0ACgBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAiAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AVgBpAHIAdQBzAFQAbwB0AGEAbAAvAHkAYQByAGEALwByAGUAbABlAGEAcwBlAHMALwBkAG8AdwBuAGwAbwBhAGQALwB2ADQALgAwAC4AMgAvAHkAYQByAGEALQB2ADQALgAwAC4AMgAtADEAMwA0ADcALQB3AGkAbgA2ADQALgB6AGkAcAAiACAALQBPAHUAdABGAGkAbABlACAAeQBhAHIAYQA2ADQALgB6AGkAcAA=

echo. unzipping...
powershell -Command Expand-Archive yara64.zip -Force

echo. Testing computer for HAFNIUM IOC's


Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\Windows\system32\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\Windows\syswow64\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\Windows\temp\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\inetpub\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* $env:exchangeinstallpath 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\Program Files (x86)\fireeye\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name HAFNIUM.yar $_.FullName 2> $null >>Warnings.txt}"

echo. Testing to see if there are warnings..
setlocal
set file=Warnings.txt
set maxbytesize=10

call :setsize %file%

:testwarnings
if %size% lss %maxbytesize% (
    goto cleanup
) else (
	echo. Saving logs to temp folder...
	COPY "Warnings.txt" "c:\temp\HAFNIUMIOC-%COMPUTERNAME%-Warnings.txt"
	echo.
	echo. Results saved in "c:\temp\HAFNIUMIOC-%COMPUTERNAME%-Warnings.txt"
    
	timeout 5
	goto cleanup
)

:setsize
set size=%~z1
goto :testwarnings

:cleanup
cd c:\temp
timeout 5
RD /S /Q c:\HAFNIUMIOC--%computername%\


exit

:::::::::::
:::::::::::    __  _____    _______   ________  ____  ___  
:::::::::::   / / / /   |  / ____/ | / /  _/ / / /  |/  /
:::::::::::  / /_/ / /| | / /_  /  |/ // // / / / /|_/ / 
::::::::::: / __  / ___ |/ __/ / /|  // // /_/ / /  / /  
:::::::::::/_/ /_/_/  |_/_/   /_/ |_/___/\____/_/  /_/   
:::::::::::    ______           __        __     ______          __
:::::::::::   / ____/  ______  / /___  (_) /_   /_  __/__  _____/ /____  _____
:::::::::::  / __/ | |/_/ __ \/ / __ \/ / __/    / / / _ \/ ___/ __/ _ \/ ___/
::::::::::: / /____>  </ /_/ / / /_/ / / /_     / / /  __(__  ) /_/  __/ /    
:::::::::::/_____/_/|_/ .___/_/\____/_/\__/    /_/  \___/____/\__/\___/_/         
:::::::::::          /_/                                                      
:::::::::::