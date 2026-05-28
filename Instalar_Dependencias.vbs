Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
base = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = base
WshShell.Run "pythonw.exe """ & base & "\instalar_dependencias.pyw""", 0, False
