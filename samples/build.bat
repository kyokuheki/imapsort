@echo off

cd /d %~dp0

pyinstaller --clean --onefile --log-level=WARN imapsort.py

@taskkill /IM imapsort.exe
@move /Y dist\imapsort.exe .\
@rmdir /Q .\build
@rmdir /Q .\dist
@rmdir /Q .\__pycache__
pause
