@echo off
setlocal EnableDelayedExpansion

:: CONFIGURE BELOW
set ILO_HOST=https://<ILO-IP>
set USER=Administrator
set PASS=YourPassword

:: HEADERS
set HEADER_Content=Content-Type: application/json

:: Get session token
echo Logging in...
curl -s -k -X POST %ILO_HOST%/redfish/v1/SessionService/Sessions -H "%HEADER_Content%" -d "{\"UserName\":\"%USER%\", \"Password\":\"%PASS%\"}" -D headers.txt -o nul

:: Extract X-Auth-Token from headers
for /f "tokens=2 delims=:" %%A in ('findstr /i "X-Auth-Token" headers.txt') do (
    set TOKEN=%%A
)

:: Clean token
set TOKEN=%TOKEN: =%
set HEADER_AUTH=X-Auth-Token: %TOKEN%

:: Define all health check endpoints (add as needed)
set ENDPOINTS=/redfish/v1/Systems/1, /redfish/v1/Systems/1/Memory, /redfish/v1/Chassis/1/Thermal, /redfish/v1/Chassis/1/Power, /redfish/v1/Managers/1

echo.
echo Checking health statuses...

:: Loop through endpoints
for %%E in (%ENDPOINTS%) do (
    echo Checking %%E...
    curl -s -k -H "%HEADER_AUTH%" -H "%HEADER_Content%" %ILO_HOST%%%E > response.json

    findstr /C:"@odata.id" response.json > members.txt

    if exist members.txt (
        :: It has members
        for /f "tokens=2 delims=:" %%M in ('type members.txt') do (
            set LINE=%%M
            set LINE=!LINE: =!
            set LINE=!LINE:"=!
            set LINE=!LINE:,=!
            echo   --> !LINE!
            curl -s -k -H "%HEADER_AUTH%" -H "%HEADER_Content%" %ILO_HOST!!LINE! > member.json
            findstr /C:"Health" member.json
        )
    ) else (
        findstr /C:"Health" response.json
    )
    echo.
)

:: Cleanup
del headers.txt >nul 2>&1
del response.json >nul 2>&1
del members.txt >nul 2>&1
del member.json >nul 2>&1

endlocal
