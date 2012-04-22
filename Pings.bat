@echo off
set network=%1
set findHost=0
echo %network%| findstr "^[0-9]*\.[0-9]*\.[0-9]*$" > NUL
if %errorlevel% NEQ 0 (
   goto usage
)
for /L %%i in (1,1,254) do (
   for /f "usebackq delims=^" %%j in (`"@ping -n 1 -w 20 %network%.%%i | findstr TTL"`) do (
      echo %%j
      set /a findHost += 1
   )
)
echo Find %findHost% hosts in %network%.*
goto :EOF
:usage
echo Example: %~n0 192.168.0
