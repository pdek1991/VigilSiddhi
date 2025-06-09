@echo off
setlocal enabledelayedexpansion

:: Base URL
set BASE_URL=http://172.19.181.141:9099/alarmapi

:: Temp file to store devices
set DEVICE_FILE=devices.json
set FILTERED_FILE=filtered_devices.txt

:: Fetch devices
echo Fetching device list...
curl -s -X GET "%BASE_URL%/v1/devices" > %DEVICE_FILE%

:: Filter out TEST-Device entries and write to text file
echo Filtering valid devices...
powershell -Command ^
  "$json = Get-Content '%DEVICE_FILE%' | ConvertFrom-Json; ^
   $json | Where-Object { $_.id -notlike 'TEST-Device*' } | ForEach-Object { $_.id }" > %FILTERED_FILE%

:: Loop and query alarms
echo.
echo Device Name       | Alarm Name        | Alarm State  | Health
echo ------------------+-------------------+--------------+---------
for /f %%D in (%FILTERED_FILE%) do (
    echo Processing device: %%D > nul
    powershell -Command ^
      "$response = Invoke-RestMethod -Uri '%BASE_URL%/v1/alarms?path=%%D' -Method Get; ^
       foreach ($alarm in $response) { ^
         $dev = '%%D'.PadRight(18); ^
         $name = ($alarm.name | Out-String).Trim().PadRight(18); ^
         $state = ($alarm.state.state | Out-String).Trim().PadRight(12); ^
         $health = ($alarm.state.latchedState | Out-String).Trim(); ^
         Write-Output \"$dev| $name| $state| $health\" ^
       }"
)

:: Cleanup
del %DEVICE_FILE%
del %FILTERED_FILE%

echo.
echo Done.
pause
