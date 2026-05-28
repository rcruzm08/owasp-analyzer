Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
base = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = base
WshShell.Run "pythonw.exe """ & base & "\launcher.pyw""", 0, False
