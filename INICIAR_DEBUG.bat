@echo off
REM Mantem janela aberta mesmo com erros
setlocal

cls
echo.
echo ========================================
echo  VALIDADOR SEC v2.0
echo ========================================
echo.

REM Teste 1: Verificar Python
echo [1/4] Verificando Python...
python --version
if %errorlevel% neq 0 (
    echo.
    echo [ERRO] Python nao encontrado!
    echo.
    echo Instale Python em: https://www.python.org/downloads/
    echo IMPORTANTE: Marque a opcao "Add Python to PATH"
    echo.
    pause
    exit /b 1
)
echo [OK] Python encontrado
echo.

REM Teste 2: Verificar pasta src
echo [2/4] Verificando estrutura...
if not exist "src" (
    echo [ERRO] Pasta 'src' nao encontrada!
    echo Execute este script na pasta raiz do projeto
    pause
    exit /b 1
)
if not exist "src\app.py" (
    echo [ERRO] Arquivo 'src\app.py' nao encontrado!
    pause
    exit /b 1
)
echo [OK] Estrutura OK
echo.

REM Teste 3: Instalar dependencias
echo [3/4] Instalando dependencias...
echo (Primeira vez pode demorar 2-5 minutos)
echo.

cd src
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo [AVISO] Algumas dependencias podem ter falhado
    echo O sistema tentara iniciar mesmo assim
    timeout /t 3 >nul
) else (
    echo.
    echo [OK] Dependencias instaladas
)

cd ..
echo.

REM Teste 4: Limpar porta 5000
echo [4/4] Verificando porta 5000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000 ^| findstr LISTENING') do (
   echo Liberando porta...
   taskkill /F /PID %%a >nul 2>&1
   timeout /t 1 >nul
)
echo [OK] Porta livre
echo.

REM Iniciar servidor
echo ========================================
echo  INICIANDO SERVIDOR
echo ========================================
echo.
echo Aguarde... Servidor iniciando em http://localhost:5000
echo.
echo IMPORTANTE: NAO FECHE ESTA JANELA!
echo (Pressione CTRL+C para encerrar o servidor)
echo.
echo ========================================
echo.

REM Aguarda 3 segundos e abre navegador
start "" cmd /c "timeout /t 3 >nul && start http://localhost:5000"

REM Inicia aplicacao
python src\app.py

REM Se chegou aqui, houve um erro
echo.
echo ========================================
echo  SERVIDOR ENCERRADO
echo ========================================
echo.

if %errorlevel% neq 0 (
    echo [ERRO] O servidor encerrou com erro
    echo.
    echo Verifique as mensagens acima para identificar o problema
) else (
    echo Servidor encerrado normalmente
)

echo.
echo Pressione qualquer tecla para fechar...
pause >nul
