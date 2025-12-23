@echo off
TITLE Instalando Correcoes...
echo.
echo ========================================
echo  CORRIGINDO DEPENDENCIAS
echo ========================================
echo.
echo [1/2] Instalando phonenumbers...
pip install phonenumbers
echo.
echo [2/2] Instalando dependencias basicas...
pip install flask requests beautifulsoup4
echo.
echo ========================================
echo  PRONTO!
echo ========================================
echo.
echo Agora feche o servidor atual e inicie novamente!
echo.
pause
