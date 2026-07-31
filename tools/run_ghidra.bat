@echo off
set JAVA_HOME=D:\11
set GHIDRA_HOME=D:\ghidra\ghidra_12.1_PUBLIC

echo Starting Ghidra headless analysis...
echo JAVA_HOME=%JAVA_HOME%
echo GHIDRA_HOME=%GHIDRA_HOME%

"%GHIDRA_HOME%\support\analyzeHeadless.bat" "C:\Users\Lenovo\Desktop\adsadsd\ghostlock-aresin\ghidra_project" kernel_analysis -import "C:\Users\Lenovo\Desktop\adsadsd\ghostlock-aresin\boot\kernel_raw" -processor ARM:LE:64:v8A -postScript FindSymbols.java -scriptPath "C:\Users\Lenovo\Desktop\adsadsd\ghostlock-aresin\tools"

echo Analysis complete.
pause
