# User Guide: SNMP Verification Tool

## Purpose

The SNMP Verification Tool validates whether listed devices are reachable and whether the configured SNMPv3 credentials can communicate with each device.

This tool is intended for authorized company use only.

## Before You Start

Confirm that you have:

- A Windows workstation.
- Network access to the devices being checked.
- An Excel workbook in `.xlsx` format.
- A workbook column named `IP Address`.
- Approved SNMPv3 usernames and AUTH/PRIV credentials for each account to be tested.

## Running the Application

1. Extract `SNMP_Verifier_Windows.zip`.
2. Open the extracted folder.
3. Run `SNMP_Verifier.exe`.
4. Select the input Excel workbook.
5. Select the number of SNMPv3 users to test. The maximum is six users.
6. Enter the username, AUTH password, and PRIV password for each SNMPv3 user.
7. Select the AUTH protocol and PRIV protocol required by the devices for each user.
8. Keep `Write SNMP debug log` selected for troubleshooting support.
9. Click `Initiate Verification`.

## Stopping a Run

Click `Stop Process` to stop the verification run. The application will save a partial report for the rows processed up to that point.

## Results

The output workbook is saved in the same folder as the selected input workbook.

`Reachability` indicates whether the device responded to ping.

For each SNMPv3 username entered in the application, the output workbook includes a matching status column:

`(<SNMPv3 username>) SNMP Status`

This column indicates whether SNMP validation succeeded for that user.

## Troubleshooting

If a device is marked `not Reachable`, confirm that the IP address is correct and that ICMP is allowed from your workstation.

If SNMP communication is not successful, confirm:

- The device is reachable on the network.
- UDP port 161 is allowed between your workstation and the device.
- The selected AUTH and PRIV protocols match the device configuration.
- The AUTH and PRIV passwords are correct.
- The device is configured for the SNMPv3 usernames entered in the application.

If the application reports a missing Python DLL, confirm that you are running `SNMP_Verifier.exe` from the extracted release folder, not from a `build_*` folder.

## Handling Output Files

Output reports and debug logs may contain device IP addresses and operational status. Handle these files according to company data handling requirements.
