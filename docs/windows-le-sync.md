# Windows LE synchronization repair

This branch fixes confirmed data flow defects in BlueVein 1.2.0. It does not
claim that an existing, rejected iPhone bond has been recovered.

## Confirmed defects

- The Windows notification handler watched the whole registry subtree but its
  snapshot contained only Classic adapter values. LE-only pairing/rekey events
  therefore did not export the new LE keys.
- The EFI importer compared the full cross-platform record with a lossy Windows
  representation. Linux-only peripheral LTK/address metadata, Classic metadata,
  and CSRK counters caused repeated writes even when Windows-storable keys agreed.
- A separate periodic importer could race the Windows export handler.
- Startup merged local-only fields into the system record but did not persist
  them back to an existing EFI device. Local change exports replaced the shared
  record and could erase fields the current backend cannot read.

## Changes and regression evidence

Windows now polls complete Classic/LE records once a second and serializes exports
before the periodic import. This reads the registry; it does not scan Bluetooth,
restart the radio, or add a service. Failed exports defer imports and remain pending.

Import comparisons use the Windows write/read representation. Unsupported fields
remain in EFI. `peripheral_ltk` is deliberately not relabeled as `ltk`: BlueZ
stores different role information, and an old rejected key is not repaired by
renaming its section.

Existing-device merges are exported at startup, local changes retain shared-only
fields, and unchanged records do not rewrite EFI. Validation errors do not print
key material.

Tests cover an IRK-only Windows record with a shared peripheral LTK, actual LTK/IRK
changes, LE-only rekey detection, local-export/import convergence, startup export
of missing fields, preservation of unrelated devices, and an actual Windows
registry round trip in an isolated HKCU fixture. CI builds Windows and Linux.

## Remaining validation

- Startup still follows upstream's EFI preference for conflicting non-null values;
  without a persisted last-synced baseline it cannot prove which offline change is
  newer. Do not claim general offline conflict resolution.
- The user's live iPhone record has no LTK in the inspected standard registry path.
  Recover the actual Windows bond source before changing keys or role mappings.
- Do not deploy over an active installation before taking private, scoped backups
  and reviewing the exact mutation. CI does not prove physical reconnection.
- Verify Windows and Linux boots with the same adapter, successful encryption and
  HID subscription, and preservation of other paired devices.
