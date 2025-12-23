@echo off
REM ========================================
REM  VALIDADOR SEC v2.0 - INICIALIZACAO SIMPLES
REM ========================================

TITLE Validador SEC v2.0

echo.
echo ========================================
echo  VALIDADOR SEC v2.0 - INICIANDO
echo ========================================
echo.

REM Verifica Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERRO] Python nao encontrado!
    echo Instale: https://www.python.org/downloads/
    pause
    exit /b
)

echo [OK] Python encontrado

REM Instala dependencias (mostra progresso)
echo.
echo [INIT] Instalando dependencias necessarias...
echo (Isso pode levar alguns minutos na primeira vez)
echo.

cd src
pip install -r requirements.txt --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo.
    echo [AVISO] Algumas dependencias falharam. Tentando sem modo silencioso...
    echo.
    pip install -r requirements.txt
)

cd ..

REM Verifica porta 5000
echo.
echo [INFO] Verificando porta 5000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000 ^| findstr LISTENING') do (
   echo [AVISO] Liberando porta 5000...
   taskkill /F /PID %%a >nul 2>&1
   timeout /t 2 /nobreak >nul
)

REM Inicia servidor
echo.
echo [INFO] Iniciando servidor Flask...
echo.
echo ========================================
echo  SERVIDOR RODANDO
echo ========================================
echo.
echo  URLs Disponiveis:
echo  - Scanner: http://localhost:5000
echo  - OSINT:   http://localhost:5000/osint
echo.
echo  Pressione CTRL+C para encerrar
echo ========================================
echo.

REM Abre navegador após 2 segundos
start "" cmd /c "timeout /t 2 >nul && start http://localhost:5000"

REM Inicia app
python src/app.py

REM Limpeza ao sair
if %errorlevel% neq 0 (
    echo.
    echo [ERRO] Servidor encerrado com erro
    pause
)
