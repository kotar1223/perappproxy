@echo off
echo Building PerAppProxy CLI...
pyinstaller --onefile --name perappproxy-cli --console --icon=NONE --add-data "src/perappproxy;perappproxy" src/perappproxy/__main__.py
echo Done: dist\perappproxy-cli.exe
