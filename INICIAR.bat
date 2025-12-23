@echo off
setlocal enabledelayedexpansion
TITLE Validador de Seguranca - Inicializando...

REM --- 1. VERIFICA PYTHON ---
echo [INFO] Verificando Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    cls
    echo.
    echo ========================================
    echo  ERRO: PYTHON NAO ENCONTRADO
    echo ========================================
    echo.
    echo Python nao esta instalado ou nao esta no PATH.
    echo.
    echo Como resolver:
    echo 1. Baixe Python em: https://www.python.org/downloads/
    echo 2. Durante instalacao, MARQUE a opcao:
    echo    [X] Add Python to PATH
    echo.
    echo Apos instalar, execute este script novamente.
    echo.
    pause
    exit /b 1
)
echo [OK] Python encontrado

REM --- 2. VERIFICA/INSTALA DEPENDENCIAS ---
echo [INIT] Verificando dependencias...
if exist src\requirements.txt (
    echo [INFO] Instalando/atualizando pacotes...
    python -m pip install --upgrade pip >nul 2>&1
    pip install -r src\requirements.txt --quiet --no-warn-script-location
    if errorlevel 1 (
        echo [AVISO] Alguns pacotes podem ter falhado. Tentando novamente com output...
        pip install -r src\requirements.txt
    ) else (
        echo [OK] Dependencias instaladas/atualizadas com sucesso.
    )
) else (
    echo [AVISO] Arquivo requirements.txt nao encontrado. Pulando.
)

REM --- 2.1 INSTALA ARSENAL ELITE (NUCLEI, SUBFINDER, FFUF) ---
echo [INIT] Verificando Arsenal Elite...
python src/modules/arsenal_installer.py

REM --- 3. CONFIGURACAO DE SEGURANCA ---
set VALIDADOR_HASH=fc66f021c67d064c1490a12b5a4d4d2f5167ca692a16ca12f1f3a4cda29a6fa9

REM --- 4. VERIFICA PORTA 5000 (AUTO-CLEAN) ---
echo [INFO] Verificando porta 5000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000 ^| findstr LISTENING') do (
   taskkill /F /PID %%a >nul 2>&1
)

REM --- 5. INICIA APLICACAO ---
echo [INFO] Iniciando servidor Flask...
start http://localhost:5000
python src/app.py

if %errorlevel% neq 0 (
    echo.
    echo [CRITICO] O servidor parou com erro.
    pause
)
