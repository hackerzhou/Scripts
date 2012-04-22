@echo off
set target=%1
if not defined target (
   goto :usage
)
for /f "usebackq delims=^" %%j in (`"@dir /ad/b/s %target% | sort /r"`) do (
   rd %%j 2>NUL
)
echo All empty folders under %target% has been deleted.
goto :EOF
:usage
echo Example: %~n0 [target_folder]
