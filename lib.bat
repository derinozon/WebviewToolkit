echo Looking for vswhere.exe...
set "vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%vswhere%" set "vswhere=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%vswhere%" (
	echo ERROR: Failed to find vswhere.exe
	exit 1
)
echo Found %vswhere%

echo Looking for VC...
for /f "usebackq tokens=*" %%i in (`"%vswhere%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
  set vc_dir=%%i
)
if not exist "%vc_dir%\Common7\Tools\vsdevcmd.bat" (
	echo ERROR: Failed to find VC tools x86/x64
	exit 1
)
echo Found %vc_dir%

call "%vc_dir%\Common7\Tools\vsdevcmd.bat" -arch=x64 -host_arch=x64

cl /I "C:\Users\admin\Documents\Github\WebviewToolkit\script\microsoft.web.webview2.1.0.664.37\build\native\include" ^
	"C:\Users\admin\Documents\Github\WebviewToolkit\script\microsoft.web.webview2.1.0.664.37\build\native\x64\WebView2Loader.dll.lib" ^
	/std:c++17 /EHsc /LD webviewtk.cpp