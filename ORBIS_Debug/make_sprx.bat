@echo off
setlocal

REM ==============================
REM RUN FSELF
REM ==============================
echo [INFO] Running fself.py ...
C:\Python27\python.exe fself.py GTAServer.prx test.sprx

if %errorlevel% neq 0 (
    echo [ERROR] fself failed.
    exit /b 1
)

echo [OK] SPRX created.

REM ==============================
REM FTP UPLOAD (WinSCP)
REM ==============================
set WINSCP="C:\Program Files (x86)\WinSCP\winscp.com"
set PS4_IP=192.168.137.241
set PS4_PORT=2121
set REMOTE_DIR=/data/GoldHEN/plugins
set FILE=test.sprx

if not exist "%FILE%" (
    echo [ERROR] %FILE% not found.
    exit /b 1
)

echo [INFO] Uploading to PS4...

%WINSCP% ^
 /command ^
 "open ftp://anonymous@%PS4_IP%:%PS4_PORT%/" ^
 "cd %REMOTE_DIR%" ^
 "put %FILE%" ^
 "exit"

if %errorlevel% neq 0 (
    echo [ERROR] FTP upload failed.
    exit /b 1
)

echo [OK] FTP upload successful.
exit /b 0
