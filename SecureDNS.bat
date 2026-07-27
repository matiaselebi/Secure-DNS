@echo off
setlocal enabledelayedexpansion

REM --- Auto-elevacion: si no corre como administrador, se relanza pidiendo permisos ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Este panel necesita permisos de administrador para el inicio automatico
    echo y para cambiar el DNS de tus adaptadores de red.
    echo Se va a pedir confirmacion de Windows...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
    exit /b
)

cd /d "%~dp0"

set TASK_NAME=SecureDNSAutostart
set PYTHONW=%~dp0venv\Scripts\pythonw.exe
set PYTHON=%~dp0venv\Scripts\python.exe
set RUN_SCRIPT=%~dp0scripts\run_dns.py
set DASHBOARD_URL=http://127.0.0.1:8890/

if not exist "%PYTHON%" (
    echo.
    echo No encontre el entorno virtual ^(venv^). Antes de usar este menu, abri
    echo una consola en esta carpeta y corre una sola vez:
    echo.
    echo     python -m venv venv
    echo     venv\Scripts\activate
    echo     pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

:menu
cls
echo ================================================
echo   SecureDNS - Panel de control  (admin)
echo ================================================
echo.
echo  1. Iniciar DNS   (ahora, en cada inicio de Windows, y como DNS de tu PC)
echo  2. Detener DNS   (y volver el DNS de tu PC a automatico)
echo  3. Ver estado
echo  4. Actualizar listas de amenazas (URLhaus + OpenPhish)
echo  5. Agregar dominio a la lista blanca (permitir siempre)
echo  6. Agregar dominio a la lista negra (bloquear siempre)
echo  7. Borrar cache de respuestas DNS
echo  8. Salir
echo.
set /p opcion="Elegi una opcion (1-8): "

if "%opcion%"=="1" goto iniciar
if "%opcion%"=="2" goto detener
if "%opcion%"=="3" goto estado
if "%opcion%"=="4" goto actualizar
if "%opcion%"=="5" goto permitir
if "%opcion%"=="6" goto bloquear
if "%opcion%"=="7" goto borrar_cache
if "%opcion%"=="8" goto salir
goto menu

:iniciar
set HUBO_ERROR=0
echo.
echo Registrando el inicio automatico con Windows...
schtasks /create /tn "%TASK_NAME%" /tr "\"%PYTHONW%\" \"%RUN_SCRIPT%\"" /sc onlogon /rl limited /f >nul 2>&1
if %errorlevel% neq 0 (
    echo   ERROR: no se pudo registrar la tarea programada.
    set HUBO_ERROR=1
) else (
    echo   OK.
)

echo Iniciando el resolver DNS ahora mismo...
if %HUBO_ERROR%==0 (
    schtasks /run /tn "%TASK_NAME%" >nul 2>&1
    if %errorlevel% neq 0 (
        echo   ERROR: no se pudo iniciar via la tarea programada.
        set HUBO_ERROR=1
    ) else (
        echo   OK.
    )
) else (
    echo   Se omite: la tarea no se registro en el paso anterior.
)
timeout /t 2 /nobreak >nul

echo Configurando 127.0.0.1 como DNS de tus adaptadores de red activos...
powershell -NoProfile -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '127.0.0.1' }" >nul 2>&1
if %errorlevel% neq 0 (
    echo   ERROR: no se pudo configurar el DNS de los adaptadores.
    set HUBO_ERROR=1
) else (
    echo   OK.
)

echo.
if %HUBO_ERROR%==0 (
    echo Listo. El resolver deberia estar corriendo, arrancando solo en cada
    echo inicio de Windows, y tu PC usandolo como DNS, hasta que elijas la
    echo opcion 2 para apagarlo.
    echo Dashboard: http://127.0.0.1:8890/
) else (
    echo Hubo al menos un error arriba. Si el puerto 53 esta ocupado por otro
    echo programa ^(otro resolver DNS, Docker, etc^), liberalo primero.
    echo Si el problema persiste, volve a intentar tras reiniciar la PC.
)
pause
goto menu

:detener
echo.
echo Quitando el inicio automatico...
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

echo Volviendo el DNS de tus adaptadores a automatico (DHCP)...
powershell -NoProfile -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }" >nul 2>&1

echo Deteniendo el proceso (si estaba corriendo)...
"%PYTHON%" scripts\stop_dns.py

echo.
echo Listo. El resolver quedo apagado, tu PC volvio a DNS automatico, y NO
echo se va a iniciar solo la proxima vez que prendas la PC.
pause
goto menu

:estado
echo.
schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if %errorlevel%==0 (
    echo Inicio automatico con Windows : ACTIVADO
) else (
    echo Inicio automatico con Windows : desactivado
)

if exist "data\dns.pid" (
    echo Proceso del resolver           : parece estar corriendo ^(PID guardado^)
) else (
    echo Proceso del resolver           : no esta corriendo
)

echo DNS actual de tus adaptadores:
powershell -NoProfile -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Write-Host ('  ' + $_.Name + ': ' + ((Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).ServerAddresses -join ', ')) }"

powershell -NoProfile -Command "try { $n = (Invoke-WebRequest -Uri '%DASHBOARD_URL%cache-count' -UseBasicParsing -TimeoutSec 3).Content; Write-Host ('Entradas en cache de respuestas : ' + $n) } catch { Write-Host 'Entradas en cache de respuestas : no disponible (el resolver no esta corriendo)' }"
echo.
pause
goto menu

:actualizar
echo.
"%PYTHON%" scripts\update_blocklist.py
echo.
pause
goto menu

:permitir
echo.
set /p NUEVO_DOMINIO="Dominio a permitir siempre (ej: ejemplo.com): "
if "%NUEVO_DOMINIO%"=="" (
    echo No ingresaste ningun dominio.
    pause
    goto menu
)
"%PYTHON%" -c "import sys; sys.path.insert(0, 'src'); from securedns.blocklist import Allowlist; Allowlist('data/allowlist.txt').add_and_reload('%NUEVO_DOMINIO%'); print('Agregado a la lista blanca:', '%NUEVO_DOMINIO%')"
echo.
echo Si el resolver esta corriendo, el cambio se aplica solo en unos segundos
echo (recarga automatica en segundo plano), sin necesidad de reiniciarlo.
echo Tambien lo podes administrar (agregar o quitar) desde el dashboard:
echo %DASHBOARD_URL%
pause
goto menu

:bloquear
echo.
set /p NUEVO_DOMINIO="Dominio a bloquear siempre (ej: ejemplo.com): "
if "%NUEVO_DOMINIO%"=="" (
    echo No ingresaste ningun dominio.
    pause
    goto menu
)
"%PYTHON%" -c "import sys; sys.path.insert(0, 'src'); from securedns.blocklist import Blocklist; Blocklist('data/blocklist.txt').add_and_reload('%NUEVO_DOMINIO%'); print('Agregado a la lista negra manual:', '%NUEVO_DOMINIO%')"
echo.
echo Si el resolver esta corriendo, el cambio se aplica solo en unos segundos
echo (recarga automatica en segundo plano), sin necesidad de reiniciarlo.
pause
goto menu

:borrar_cache
echo.
echo Esto borra el cache de respuestas DNS (en memoria). La proxima consulta
echo de cualquier dominio se le vuelve a pedir al servidor upstream en vez
echo de responderse desde una respuesta guardada. Solo tiene efecto si el
echo resolver esta corriendo (el cache no persiste en disco).
set /p CONFIRMA="Confirmar? (s/n): "
if /i not "%CONFIRMA%"=="s" (
    echo Cancelado.
    goto menu
)
echo.
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri '%DASHBOARD_URL%clear-cache' -UseBasicParsing -TimeoutSec 3 | Out-Null; Write-Host '  OK: cache borrado.' } catch { Write-Host '  El resolver no parece estar corriendo, no hay nada que borrar.'; exit 1 }"
pause
goto menu

:salir
endlocal
exit /b 0
