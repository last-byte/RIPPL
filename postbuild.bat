cd %0\..\
python3.exe .\restore_headers.py
rem python3.exe .\carboncopy.py www.crowdstrike.com 443 .\x64\Release\RIPPL_unsigned.exe .\x64\Release\RIPPL.exe
python3.exe .\sigthief.py -i C:\Windows\System32\services.exe -t .\x64\Release\RIPPL_unsigned.exe -o .\x64\Release\RIPPL.exe