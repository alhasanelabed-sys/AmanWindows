# Verification evidence

Version: 1.0.0
Target: Windows 10/11 desktop, Windows PowerShell 5.1, WinForms.
Executed test environment: Linux, Microsoft PowerShell 7.4.6.

- Test-Guard.ps1: 27 passed, 0 failed, exit 0.
- Parser: 5 PowerShell files, 0 errors, exit 0.
- Independent report/GUI helper fixtures: malicious HTML encoding, Arabic JSON, empty and deserialized sections, path quoting passed.
- Repair and restoration tests use module-isolated substitutes, not actual Windows protection changes.
- Actual Windows PowerShell 5.1, WinForms and live Windows native protection/CIM commands: NOT EXECUTED; require Windows validation.
- No user device was inspected or modified.

Run on Windows from the extracted folder:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File .\tests\Test-Guard.ps1
```

The fixture tests do not replace Windows integration validation.
