@echo off
powershell.exe -Command "Start-Process -Verb RunAs -FilePath powershell -ArgumentList '-ExecutionPolicy Bypass -File ""%cd%\libs\main.ps1""'