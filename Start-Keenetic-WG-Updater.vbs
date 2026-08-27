Option Explicit
Dim shell, fso, folder, scriptPath, logPath, cmd, rc
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
folder = fso.GetParentFolderName(WScript.ScriptFullName)
scriptPath = fso.BuildPath(folder, "Keenetic-WG-Updater.ps1")
logPath = fso.BuildPath(folder, "startup-error.log")

On Error Resume Next
If fso.FileExists(logPath) Then fso.DeleteFile logPath, True
On Error GoTo 0

cmd = "cmd.exe /d /c powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & scriptPath & """ 1>nul 2>""" & logPath & """"
rc = shell.Run(cmd, 0, True)

If rc <> 0 Then
    MsgBox "Keenetic WG Updater не запустился." & vbCrLf & vbCrLf & _
           "Ошибка сохранена сюда:" & vbCrLf & logPath & vbCrLf & vbCrLf & _
           "Пришли startup-error.log — там будет точная причина.", _
           vbCritical, "Keenetic WG Updater"
End If
