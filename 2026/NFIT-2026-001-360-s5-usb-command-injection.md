# NFIT-2026-001: Root command injection in the 360 S5 robot vacuum USB update

| | |
|---|---|
| Advisory | NFIT-2026-001 |
| Vendor | Qihoo 360 |
| Product | 360 S5 robot vacuum |
| Affected firmware | 1.4.1.1170, 1.8.2.2363, 1.8.5.2515, 1.8.5.2570, 1.8.7.2770, 1.8.9.2976 (latest offered by the vendor at time of writing) |
| Component | `/app/watchDoge`, USB stick update routine |
| Type | OS command injection (CWE-78) |
| Severity | CVSS 3.1: 6.8 Medium (`AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| CVE | Requested through VulDB, pending |
| Status | Reported to the vendor 2026-11-23, no fix available |
| Credit | Jeremie P. (NetworkFixIT) |

## Summary

The robot can update itself from a USB stick. The update routine in `watchDoge` puts the name of the update file straight into a shell command and runs it as root. A file name containing `;` runs any command the attacker adds. Anyone with a few seconds of physical access to the robot and a prepared USB stick gets full root control.

## Details

When a USB stick is mounted at `/tmp/sd`, `watchDoge` lists the `/tmp/sd/ota` folder and looks for an update file. The file is accepted when:

- its name contains `.pack`,
- it is larger than 50,000 bytes,
- it is the only such file in the folder.

The routine then builds the command

```
cp -f <full path of the .pack file> /tmp/ota.zip
```

by plain string concatenation and passes it to `system()`, which runs it through `/bin/sh` as root. The path is not quoted or filtered. In firmware 1.8.9.2976 this code sits around address `0x428080` to `0x428114` of `watchDoge`. The same `cp -f ` and `/tmp/ota.zip` strings and the same routine are present in all six firmware versions listed above.

The bug was confirmed on a device running 1.8.9.2976.

## Proof of concept

A file name cannot contain `/`, so the injected commands change directory step by step to reach the stick, then run a script stored on it.

USB stick layout (FAT32):

```
ota/
  a;cd ..;cd ..;cd ..;cd ..;cd ..;cd tmp;cd sd;id>proof.txt;echo .pack    (any content, over 50,000 bytes)
```

Insert the stick into the robot. After a few seconds, `proof.txt` on the stick contains:

the output of `id`, showing `uid=0(root)`.

Replacing `id>proof.txt` with `sh r.sh` runs a full script from the stick root as root.

## Impact

- Full root access with brief physical access, no account and no user interaction.
- Persistent changes: the `/app` and `/userdata` partitions are writable, so an attacker can leave software that survives reboots.
- The robot stores the home Wi-Fi credentials and floor maps, so a tampered robot is a foothold in the home network.
- Second-hand and returned units are exposed: the previous holder can leave a backdoor.

## Fix

- Do not run the copy through a shell. Copy the file in code (open, read, write), or use `rename()`, or `execv("/bin/cp", ...)` with the path as its own argument.
- Accept only update file names that match a strict pattern (letters, digits, `.`, `-`, `_`).
- Check the update signature before acting on the file, not after.

## Workaround for owners

Until a fixed firmware exists, keep the robot where strangers cannot plug in a USB stick, and treat second-hand units as untrusted until reset and checked.

## Timeline

- 2026-11-15: issue found and confirmed on 1.8.9.2976
- 2026-11-23: all six published firmware versions checked
- 2026-11-23: reported to Qihoo 360 (security@360.cn), correction to the proof-of-concept file name sent the same day
- 2026-11-23: CVE requested through VulDB
- 2026-11-23: this advisory published
