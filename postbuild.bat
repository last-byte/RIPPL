cd %0\..\
python3.exe .\restore_headers.py
python3.exe .\carboncopy.py www.crowdstrike.com 443 .\x64\Release\RIPPL_unsigned.exe .\x64\Release\RIPPL.exe
del .\x64\Release\RIPPL_unsigned.exe
del .\x64\Release\RIPPLDLL_unencrypted.dll
del .\x64\Release\RIPPLDLL.dll
echo [+] Successfully run postbuild.bat