# Windows LE identity synchronization repair

## Linux compatibility for an existing Windows-format IRK

On the tested host, the shared iPhone IRK bytes resolve its advertised RPA only
after reversal at the Linux storage boundary. A scoped Linux override is available:
`BLUEVEIN_LINUX_REVERSE_IRK_PEERS=44:F7:9F:AC:CD:9C/10:A2:D3:01:47:A1`.
Multiple adapter/peer pairs may be comma-separated. Invalid entries fail startup.
The conversion applies symmetrically on Linux read and write, preserving the shared
EFI representation and compatibility with the deployed Windows binary. It does
not reverse LTKs or change unlisted bonds. This is an explicit compatibility
setting, not automatic format detection or a global key-format migration.

The same host required `Privacy=off` in BlueZ for its public controller identity
to be recognized by the existing iPhone bond. With a reversed Linux IRK, original
LTK, and public host address, the physical capture showed successful AES-CCM
encryption and Linux created keyboard/mouse HID devices. Reversing LTK did not
help. This adapter-wide privacy choice exposes the public Bluetooth address;
reboot and return-to-Windows acceptance remain required. Other devices and Macs
must retain their pairing/channel settings.

## Root cause verified on a dual-boot host

Windows stored the working HID bond under a pairing-time resolvable private
address. Its registry `Address` value identified the public peer identity used by
Linux. BlueVein 1.2.0 indexed the shared record by the registry subkey name and
ignored `Address` and `AddressType`. Correct Windows LTK/IRK values reached EFI,
but under the temporary address, while the Linux identity record retained an old
LTK and a different IRK.

A separate public-address Windows entry contained only the stale IRK. The fix
prefers the complete identity-mapped bond, refuses conflicting complete bonds,
and routes imports back to the real Windows storage entry.

## Repair and invariants

- Export/import uses the peer identity and its public/static-random address type.
- Legacy EFI aliases migrate only when their LTK, IRK, EDIV, Rand and key length
  match the live Windows bond. Mismatches stop automatic migration.
- Classic keys and other devices are retained. A stale peripheral LTK is replaced
  by the current SC key only for a verified Secure Connections bond; unresolved
  legacy role-specific conflicts stop migration.
- Windows AuthReq SC metadata and zero EDIV/Rand map to the BlueZ MGMT P-256 key
  type. Requested MITM alone is not treated as proof of authentication. Windows
  writes use its boolean Authenticated representation and preserve other flags.
- Missing metadata in older exports does not downgrade the same known LTK.
- Complete Classic/LE snapshots serialize local exports before periodic imports.
- Platform-only metadata does not cause endless import loops; unchanged state
  does not rewrite EFI. Read/import errors stop synchronization.
- Windows service status interrogation no longer requests shutdown.

The Linux key type/role behavior is documented by BlueZ MGMT and Linux
`hci_find_ltk`: Secure Connections keys apply independently of central/peripheral
role. Legacy role-specific keys are not interchangeable.

## Commands

`bluevein.exe audit-sync [adapter-mac identity-mac]` runs the same planning code
without modifying the registry or EFI keys. Its diagnostics do not print secrets.

`bluevein.exe repair-efi-only [adapter-mac identity-mac]` writes the shared config
but refuses any plan that would update local Windows keys. Scope the first repair
to the affected peer; take a private backup and stop the old sync service first.

`bluevein.exe sync-once [adapter-mac identity-mac]` performs one synchronization.
Normal service operation remains automatic for all devices.

## Validation and limits

CI exercises real registry round trips in isolated HKCU fixtures, identity/RPA
migration with a stale IRK-only shadow, conflict rejection, SC metadata, LE rekey
handling, unchanged-state behavior, failure handling, and service control. It
builds both Windows and Linux.

A live read-only audit verified that the affected peer's migration requires no
Windows key writes. Deployment additionally checks key equality, unchanged other
EFI records, unchanged Windows registry values, and the actual service process.

Physical Linux reconnect and subsequent Windows return must still be tested.
Startup retains upstream EFI precedence for unrelated conflicting offline edits;
there is no persisted three-way conflict history. This branch must not be described
as resolving arbitrary simultaneous offline pairing changes.

## Deployed Windows validation (2026-09-20)

Commit `4b28aa3` passed 40 Windows tests and 27 Linux tests, with release builds
for both platforms. Its Windows binary was installed as the existing service
using a protected ProgramData directory.

The scoped repair verified current registry LTK/IRK equality at the canonical EFI
identity, removal of the legacy alias, preservation of all other EFI records at
the repair checkpoint, and byte-for-byte preservation of Windows registry values
before and after starting the replacement service. Private pre-change backups
are DPAPI-protected with restricted ACLs. Bluetooth radio/service was not restarted.

The replacement service remained running across multiple periodic checks without
new key-mismatch or error messages. Physical Linux reconnect and return-to-Windows
validation remain outstanding; these results are not a claim of completed hardware
validation.

## Test candidate after the initial deployment

EFI writes now require a complete configuration read-back match. Missing or
unreadable output is an error, so the Windows monitor retries the export before
allowing another import. Linux startup also propagates a failed initial sync
instead of entering its export monitor after an incomplete import.

Regression coverage includes dropped writes, unreadable read-back, retry after a
failed export, both SC security types during rekey, and conflicting complete
Windows identity records. CI runs on pull requests as well as the fork branch.

### Hardware acceptance checklist

1. Keep the existing pairing and boot Linux. Confirm EFI and BlueZ identity,
   LTK/IRK and role-key equality privately; never paste key files into an issue.
2. Verify cursor movement and keyboard input, then disconnect/reconnect the app.
3. Suspend/resume Linux and repeat input and reconnect checks.
4. Boot Windows again and repeat input/reconnect checks. Confirm the service
   remains running and does not repeatedly rewrite unchanged keys.
5. Confirm headphones and the pre-existing Mac pairing still work.

Record OS/BlueZ versions, tested binary commit, pass/fail for each step, and
sanitized error/event summaries. Do not claim hardware validation from CI.

## Follow-up candidate validation (2026-09-20)

Commit `3785471` passed 45 Windows tests and 30 Linux tests, with both release
builds. It was deployed over the initial fix using the same backup, audit and
registry-preservation checks. The maintainer confirmed cursor and keyboard input
still work in Windows. Linux hardware and return-to-Windows checks remain pending.
