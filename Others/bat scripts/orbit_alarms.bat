@echo off
setlocal EnableDelayedExpansion

:: ---------------------------------------------
:: CONFIGURATION
:: ---------------------------------------------
set ORBIT_HOST=https://your-gv-orbit-server
set ALARM_API=/api/alarms
set USER=admin
set PASS=yourpassword
set OUTFILE=alarms_report.txt

:: ---------------------------------------------
:: Clean previous output
:: ---------------------------------------------
if exist %OUTFILE% del %OUTFILE%

:: ---------------------------------------------
:: Write header
:: ---------------------------------------------
echo "Severity","Source","Message","Timestamp" >> %OUTFILE%

:: ---------------------------------------------
:: Fetch alarms
:: ---------------------------------------------
echo Fetching current alarms from GV Orbit...
curl -s -k -u %USER%:%PASS% %ORBIT_HOST%%ALARM_API% > response.json

:: ---------------------------------------------
:: Parse and format alarms manually
:: ---------------------------------------------
for /f "tokens=*" %%L in ('type response.json ^| findstr /C:"severity" /C:"source" /C:"message" /C:"timestamp"') do (
    set LINE=%%L
    set LINE=!LINE: =!
    set LINE=!LINE:"=!
    set LINE=!LINE:,=!
    if "!LINE!"=="severity:" (
        set /p SEVERITY=<nul
        set SEVERITY=%%L
    )
    if "!LINE!"=="source:" (
        set SOURCE=%%L
    )
    if "!LINE!"=="message:" (
        set MESSAGE=%%L
    )
    if "!LINE!"=="timestamp:" (
        set TIMESTAMP=%%L
        >> %OUTFILE% echo "!SEVERITY:~9!","!SOURCE:~7!","!MESSAGE:~8!","!TIMESTAMP:~10!"
    )
)

:: ---------------------------------------------
:: Done
:: ---------------------------------------------
echo.
echo Alarm collection complete.
echo Output saved to: %OUTFILE%

endlocal
