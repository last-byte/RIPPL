cd %0\..\
python3.exe .\restore_headers.py
python3.exe .\sigthief.py -i C:\Windows\System32\services.exe -t .\x64\Release\RIPPL_unsigned.exe -o .\x64\Release\RIPPL.exe
del .\x64\Release\RIPPL_unsigned.exe
del .\x64\Release\RIPPLDLL_unencrypted.dll
del .\x64\Release\RIPPLDLL.dll
echo [+] Successfully run postbuild.bat