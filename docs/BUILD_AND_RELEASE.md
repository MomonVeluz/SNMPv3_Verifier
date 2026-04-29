# Build and Release Guide

## Purpose

This document describes how to build the SNMP Verification Tool for Windows distribution.

## Prerequisites

- Windows 10 or later.
- Python 3.11.
- Access to the project repository.

## Create Development Environment

From the repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run From Source

```powershell
.\.venv\Scripts\Activate.ps1
python app\snmpv3_verifier.py
```

## Build Executable Package

```powershell
.\.venv\Scripts\Activate.ps1
cd app
pyinstaller --noconfirm SNMP_Verifier.spec
```

The packaged application is created at:

`app/dist/SNMP_Verifier`

## Prepare User Distribution ZIP

From the repository root:

```powershell
New-Item -ItemType Directory -Force -Path release | Out-Null
Compress-Archive -Path app\dist\SNMP_Verifier\* -DestinationPath release\SNMP_Verifier_Windows.zip -Force
```

## Distribution Rule

Always distribute the full packaged folder or ZIP. Do not distribute only `SNMP_Verifier.exe`.

The executable requires the adjacent `_internal` folder created by PyInstaller.

## Folders Not Intended for Distribution

Do not distribute or run executables from:

- `app/build`
- `app/build_*`

These folders are intermediate PyInstaller build workspaces and do not contain the complete runtime package.
