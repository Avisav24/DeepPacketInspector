@echo off
REM ============================================================
REM  DPI Engine - Java Build Script
REM  Usage: build.bat
REM  Output: out\dpi.jar
REM ============================================================

set "JAVAC=%JAVA_HOME%\bin\javac.exe"
set "JAR_TOOL=C:\Program Files\Java\jdk-25\bin\jar.exe"
set "SRC_ROOT=%~dp0src\main\java"
set "OUT_DIR=%~dp0out"

echo [BUILD] Creating output directory...
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo [BUILD] Collecting source files...
dir /s /b "%SRC_ROOT%\*.java" > "%OUT_DIR%\sources.txt"

echo [BUILD] Compiling...
"%JAVAC%" -d "%OUT_DIR%" "@%OUT_DIR%\sources.txt"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Compilation failed!
    exit /b 1
)

echo [BUILD] Creating MANIFEST...
echo Main-Class: com.dpi.Main > "%OUT_DIR%\MANIFEST.MF"

echo [BUILD] Packaging JAR...
"%JAR_TOOL%" cfm "%OUT_DIR%\dpi.jar" "%OUT_DIR%\MANIFEST.MF" -C "%OUT_DIR%" com
if %ERRORLEVEL% neq 0 (
    echo [ERROR] JAR creation failed!
    exit /b 1
)

echo.
echo [SUCCESS] Build complete!
echo           JAR: %OUT_DIR%\dpi.jar
echo.
echo Usage:
echo   java -jar out\dpi.jar ^<input.pcap^> ^<output.pcap^> [options]
echo   java -jar out\dpi.jar ^<input.pcap^> ^<output.pcap^> --block-app YouTube
echo   java -jar out\dpi.jar ^<input.pcap^> ^<output.pcap^> --block-ip 192.168.1.50
echo   java -jar out\dpi.jar ^<input.pcap^> ^<output.pcap^> --block-domain facebook
