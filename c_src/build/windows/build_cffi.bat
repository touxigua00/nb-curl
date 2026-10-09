@echo off
REM 编译 nb_curl 的 CFFI API 模式扩展（Windows / MSVC）
REM
REM 先跑 vcvars64 备好 MSVC 环境，再让 setuptools 直接复用它
REM （DISTUTILS_USE_SDK=1 + MSSdk=1），避免它自己去注册表找 VS。
REM
REM vcvars64.bat 会自动探测；也可以先用 NB_CURL_VCVARS 指定完整路径。

setlocal

set "VCVARS=%NB_CURL_VCVARS%"
if defined VCVARS goto have_vcvars

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto no_vcvars
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINST=%%i"
if not defined VSINST goto no_vcvars
set "VCVARS=%VSINST%\VC\Auxiliary\Build\vcvars64.bat"

:have_vcvars
if not exist "%VCVARS%" (
  echo [ERROR] vcvars64.bat 不存在: %VCVARS%
  exit /b 1
)
call "%VCVARS%" >nul
if errorlevel 1 (
  echo [ERROR] vcvars64.bat 调用失败
  exit /b 1
)

set DISTUTILS_USE_SDK=1
set MSSdk=1
set "CL=/utf-8"
set http_proxy=
set https_proxy=
set all_proxy=

cd /d "%~dp0..\..\python"
".venv\Scripts\python.exe" -m nb_curl._cffi_build %*
if errorlevel 1 (
  echo [ERROR] CFFI 编译失败
  exit /b 1
)
echo NB_CURL-CFFI-WRAPPER-OK
endlocal
exit /b 0

:no_vcvars
echo [ERROR] 找不到 vcvars64.bat。
echo         请安装 Visual Studio 2022（勾选「使用 C++ 的桌面开发」），
echo         或用 NB_CURL_VCVARS 指定它的完整路径。
exit /b 1
