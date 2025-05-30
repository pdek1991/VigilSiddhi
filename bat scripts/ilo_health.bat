@echo off
setlocal EnableDelayedExpansion

REM ----------------------------
REM Configuration
REM ----------------------------
set ILO_IP=192.168.1.100
set USER=admin
set PASS=your_password
set BASE_URL=https://%ILO_IP%/redfish/v1
set CURL_OPTS=-sk

echo Connecting to iLO at %ILO_IP%...
echo Fetching health status...
echo.

REM ----------------------------
REM Function to get health using PowerShell
REM ----------------------------
REM Usage: call :get_health_status "endpoint" "Component Name"
:get_health_status
set "endpoint=%~1"
set "component=%~2"

REM Fetch JSON using curl
curl %CURL_OPTS% -u %USER%:%PASS% "%BASE_URL%/%endpoint%" -o temp_component.json

REM Use PowerShell to parse and display health
for /f "delims=" %%A in ('powershell -Command ^
    "Try {
        $data = Get-Content -Raw -Path 'temp_component.json' | ConvertFrom-Json;
        $health = $data.Status.Health;
        $state = $data.Status.State;
        Write-Output '%component%:';
        Write-Output ('  Health: ' + $health);
        Write-Output ('  State : ' + $state);
    } Catch {
        Write-Output '%component%:';
        Write-Output '  Unable to parse or fetch data.';
    }"
') do (
    echo %%A
)
echo.
goto :eof

REM ----------------------------
REM Check major components
REM ----------------------------
call :get_health_status "Systems/1" "System"
call :get_health_status "Systems/1/Memory" "Memory"
call :get_health_status "Systems/1/Processors" "Processors"
call :get_health_status "Chassis/1/Thermal" "Thermal (Temperature/Fans)"
call :get_health_status "Chassis/1/Power" "Power Supply"
call :get_health_status "Systems/1/Storage" "Storage Summary"

REM ----------------------------
REM Optional: loop over drives
REM ----------------------------
REM Fetch list of drive endpoints
curl %CURL_OPTS% -u %USER%:%PASS% "%BASE_URL%/Systems/1/Storage/1/Drives" -o drives.json

REM Extract members and loop
powershell -Command ^
    "$d = Get-Content -Raw -Path 'drives.json' | ConvertFrom-Json; ^
    $d.Members | ForEach-Object { $_.'@odata.id' }" > drive_list.txt

for /f "tokens=* delims=" %%D in (drive_list.txt) do (
    set "drivePath=%%D"
    set "cleanPath=!drivePath:/redfish/v1/=!"
    call :get_health_status "!cleanPath!" "Drive: %%D"
)

del temp_component.json >nul 2>&1
del drives.json >nul 2>&1
del drive_list.txt >nul 2>&1

echo Hardware health check completed.
pause
