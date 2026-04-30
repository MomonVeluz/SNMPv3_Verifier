# SNMP Verification Tool

## Overview

The SNMP Verification Tool is a Windows desktop application for validating device reachability and SNMPv3 credential access against a list of device IP addresses.

The application reads an Excel workbook, checks each device for network reachability, attempts SNMPv3 validation using one to six user-supplied SNMPv3 accounts, and writes a timestamped Excel results file.

## Current Release Package

The prepared Windows package is available at:

`release/SNMP_Verifier_Windows.zip`

To distribute the application to company users, provide the ZIP file. Users must extract the full ZIP contents before running the application.

## For End Users

1. Extract `SNMP_Verifier_Windows.zip` to a local folder.
2. Open the extracted folder.
3. Run `SNMP_Verifier.exe`.
4. Select an `.xlsx` workbook that contains a column named `IP Address`.
5. Select the number of SNMPv3 users to test. The maximum is six users.
6. Enter the username, AUTH password, and PRIV password for each SNMPv3 user.
7. Select the required AUTH and PRIV protocols for each user.
8. Leave `Write SNMP debug log` enabled unless directed otherwise.
9. Click `Initiate Verification`.

The application creates a new Excel report in the same folder as the input workbook.

## Input File Requirements

The input workbook must be an `.xlsx` file and must include a column named:

`IP Address`

Each row in this column should contain one IPv4 address.

## Output Files

For a completed run, the application creates:

`<input_file_name>_SNMP_RESULTS_FINAL_<timestamp>.xlsx`

If the run is stopped before completion, the application creates:

`<input_file_name>_SNMP_RESULTS_PARTIAL_<timestamp>.xlsx`

When debug logging is enabled, the application also creates:

`<output_file_name>_DEBUG.log`

## Output Columns

The generated Excel report includes:

- `Reachability`
- `(<SNMPv3 username>) SNMP Status` for each user entered in the application.

## Security Notes

- The application does not save SNMP passwords.
- Username and password values are entered at runtime by the user.
- Password fields are masked in the user interface.
- Passwords are not written to the Excel report or debug log.
- The debug log records IP-level test results and SNMP response details for troubleshooting.
- Use this tool only on authorized company networks and approved device inventories.

## Developer Setup

Use a clean Python environment. Do not commit virtual environment folders to the repository.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app\snmpv3_verifier.py
```

## Build Windows Package

From the repository root:

```powershell
.\.venv\Scripts\Activate.ps1
cd app
pyinstaller --noconfirm SNMP_Verifier.spec
```

The build output is created under:

`app/dist/SNMP_Verifier`

For company distribution, zip the entire `SNMP_Verifier` folder. The executable must remain together with its `_internal` folder.

## Repository Contents

- `app/snmpv3_verifier.py` - Main application source.
- `app/SNMP_Verifier.spec` - PyInstaller build configuration.
- `app/app.ico` - Application icon.
- `docs/USER_GUIDE.md` - Formal user operating guide.
- `docs/BUILD_AND_RELEASE.md` - Developer build and release guide.
- `release/SNMP_Verifier_Windows.zip` - Prepared Windows release package.
