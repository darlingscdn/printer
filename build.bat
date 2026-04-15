@echo off
set GPP=%LOCALAPPDATA%\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260407-ucrt-x86_64\bin\g++.exe
set ROOT=%~dp0

@rem dont try and remove bin folder because i did not make it so that it will create if it does not exist so just dont delete it
"%GPP%" -std=c++17 -O2 -s -static-libgcc -static-libstdc++ -o "%ROOT%bin\printer.exe" "%ROOT%inject\main.cpp" "%ROOT%inject\inject.cpp"
if %errorlevel%==0 (echo printer.exe: Built) else (echo printer.exe: Failed)

"%GPP%" -std=c++17 -O2 -s -static-libgcc -static-libstdc++ -o "%ROOT%bin\update.exe" "%ROOT%update\update.cpp"
if %errorlevel%==0 (echo update.exe: Built) else (echo update.exe: Failed)
