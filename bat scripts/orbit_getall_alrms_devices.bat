@echo off
setlocal enabledelayedexpansion

set "API_URL=http://172.19.181.141:9099/alarmapi"
set "DEVICE_API=%API_URL%/v1/devices"
set "TMP_DEVICES=devices.txt"
set "TMP_ALARMS=alarms.txt"

:: Fetch device list
curl -s -X GET "%DEVICE_API%" > %TMP_DEVICES%

:: Print header
echo Device Name           | Alarm Name            | Alarm State    | Health
echo ----------------------|------------------------|----------------|--------

:: Loop through lines to find device names (skip TEST_DEvice)
for /f "tokens=2 delims=:," %%A in ('findstr /i "name" %TMP_DEVICES%') do (
    set "device=%%~A"
    set "device=!device:"=!"
    set "device=!device: =!"

    echo !device! | findstr /B /C:"TEST_DEvice" >nul
    if errorlevel 1 (
        :: Fetch alarms for this device
        curl -s -X GET "%API_URL%/v1/alarms?path=!device!" > %TMP_ALARMS%

        :: Parse alarms
        for /f "tokens=2,4,6 delims=:,{}" %%X in ('findstr /i /C:"name" /C:"state" /C:"health" %TMP_ALARMS%') do (
            set "alarmName=%%~X"
            set "state=%%~Y"
            set "health=%%~Z"

            set "alarmName=!alarmName:"=!"
            set "state=!state:"=!"
            set "health=!health:"=!"

            echo !device!               | !alarmName!              | !state!         | !health!
        )
    )
)

:: Cleanup
del %TMP_DEVICES% >nul 2>&1
del %TMP_ALARMS% >nul 2>&1

endlocal
pause
