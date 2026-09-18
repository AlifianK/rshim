@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "SHIM_SOURCE=%~dp0target\release\rshim.exe"
if not exist "%SHIM_SOURCE%" (
  echo Missing build: "%SHIM_SOURCE%". Run cargo build --release first. 1>&2
  exit /b 1
)
if not defined SCOOP set "SCOOP=%USERPROFILE%\scoop"
if not defined SCOOP_GLOBAL set "SCOOP_GLOBAL=%ProgramData%\scoop"
set "SHIM_FAILED=0"
call :replace "%SCOOP%\shims"
call :replace "%SCOOP_GLOBAL%\shims"
exit /b %SHIM_FAILED%

:replace
if not exist "%~1\*.exe" exit /b 0
for %%x in ("%~1\*.exe") do (
  rem A matching sidecar identifies a shim; leave other executables alone.
  if exist "%%~dpnx.shim" (
    echo Replacing "%%~x".
    copy /B /Y "%SHIM_SOURCE%" "%%~x" >NUL
    if errorlevel 1 (
      echo Failed to replace "%%~x". 1>&2
      set "SHIM_FAILED=1"
    )
  )
)
exit /b 0
