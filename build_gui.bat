@echo off
echo Building PerAppProxy GUI...
pyinstaller --onefile --name PerAppProxy --windowed --icon=NONE --add-data "src/perappproxy;perappproxy" src/perappproxy/gui.py
echo Done: dist\PerAppProxy.exe
