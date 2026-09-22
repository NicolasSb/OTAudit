# Passive audit of industrial traffic

**Engagement.** Passive audit - Site A control network
**Authorisation.** J. Martin, maintenance manager, reference BC-2026-014
**Authorised window.** 2023-11-14T20:00:00+00:00 to 2023-11-15T02:00:00+00:00
**Report generated.** 2026-09-21T11:47:06+00:00

Capture taken on the mirrored port of the control switch, no injection. Supervision and engineering VLANs only.


## Capture

| | |
| --- | --- |
| File | `samples/demo.pcap` |
| First packet | 2023-11-14T22:13:20+00:00 |
| Last packet | 2023-11-14T22:13:53.419000+00:00 |
| Duration | 33 s |
| TCP segments | 255 |
| Industrial frames | 253 |
| Truncated records | 0 |
| Stream gaps | 0 |
| Within authorised window | yes |

## Devices

| Address | Role | Protocol | Unit IDs | Identification | Other services | Scope |
| --- | --- | --- | --- | --- | --- | --- |
| 10.42.7.10 | client | - | - | - | - | in |
| 10.42.7.11 | client | - | - | - | - | in |
| 10.42.7.20 | server | modbus | 1 | - | 23 | in |
| 10.42.7.21 | server | modbus | 1 | TM241CE40R / 5.1.9.9 / Schneider Electric | - | in |
| 10.42.7.22 | server | modbus | 1 | - | - | in |
| 10.42.7.30 | server | s7comm | - | 6ES7 214-1AG40-0XB0 / CPU 1214C DC/DC/DC / LINE2_CPU | - | in |
| 10.42.9.80 | client | - | - | - | - | outside |

## Exchanges

| Client | Server | Protocol | Requests | Responses | Writes | Exceptions | Mean interval |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 10.42.7.10 | 10.42.7.20:502 | modbus | 41 | 41 | 1 | 0 | 750 ms |
| 10.42.9.80 | 10.42.7.20:502 | modbus | 1 | 1 | 1 | 0 | - |
| 10.42.7.10 | 10.42.7.21:502 | modbus | 41 | 41 | 0 | 0 | 782 ms |
| 10.42.7.10 | 10.42.7.22:502 | modbus | 40 | 40 | 0 | 20 | 750 ms |
| 10.42.7.11 | 10.42.7.30:102 | s7comm | 3 | 4 | 1 | 0 | 415 ms |

- `10.42.7.10 -> 10.42.7.20:502`: read holding registers (40), write multiple registers (1)
- `10.42.9.80 -> 10.42.7.20:502`: write single register (1)
- `10.42.7.10 -> 10.42.7.21:502`: encapsulated interface transport (1), read holding registers (40)
- `10.42.7.10 -> 10.42.7.22:502`: read holding registers (40)
- `10.42.7.11 -> 10.42.7.30:102`: cpu services (1), setup communication (1), write variable (1)

## Findings

### OT-003 - Several hosts write to the same device

**Severity.** high
**Assets.** 10.42.7.20
**References.** CR 2.1 / Mesure 12 (gestion des droits)

Observed:

- 10.42.7.20 written by 10.42.7.10, 10.42.9.80

Identify each writer and the reason it exists. A second master is usually a maintenance laptop or a supervision station left connected after commissioning; concurrent writes to the same registers also cause process incidents that are hard to attribute.

### OT-008 - Legacy management services reachable on the control segment

**Severity.** high
**Assets.** 10.42.7.20
**References.** CR 1.1 / CR 4.1 / CR 7.6 / Mesure 14 (durcissement) / Mesure 19 (protocoles)

Observed:

- 10.42.7.20: telnet/23

Disable the services that are not required for operation. Where an HMI or a gateway genuinely needs them, restrict the source addresses and stop using the ones that carry credentials in clear.

### OT-001 - Control traffic carried without authentication or integrity protection

**Severity.** medium
**Assets.** 10.42.7.20, 10.42.7.21, 10.42.7.22, 10.42.7.30
**References.** CR 3.1 / CR 4.1 / Mesure 15 (cloisonnement) / Mesure 19 (protocoles)

Observed:

- modbus observed in clear text on the mirrored segment
- s7comm observed in clear text on the mirrored segment

Neither Modbus/TCP nor S7comm carries authentication. Compensate at the network layer: dedicated VLAN, filtering between the control segment and everything else, and no route from office IT to port 502 or 102.

### OT-002 - Write operations observed on the control network

**Severity.** medium
**Assets.** 10.42.7.20, 10.42.7.30
**References.** CR 1.2 / CR 2.1 / Mesure 12 (gestion des droits)

Observed:

- 10.42.7.10 -> 10.42.7.20:502 - 1 write requests
- 10.42.9.80 -> 10.42.7.20:502 - 1 write requests
- 10.42.7.11 -> 10.42.7.30:102 - 1 write requests

Confirm with the operator that each writing host is a legitimate controller. Any host able to reach port 502 or 102 can issue the same requests, so the control list is whatever the firewall allows, not what the application intends.

### OT-005 - Industrial hosts seen outside the declared target ranges

**Severity.** medium
**Assets.** 10.42.9.80
**References.** CR 1.2 / Mesure 1 (cartographie)

Observed:

- 10.42.9.80 (client) not covered by scope targets

The asset inventory used to write the scope does not match the traffic. Reconcile before drawing any conclusion from the rest of this report: an audit that missed a device also missed its exposure.

### OT-007 - Recurrent protocol exceptions

**Severity.** low
**Assets.** 10.42.7.22
**References.** CR 7.2 / Mesure 17 (journalisation)

Observed:

- 10.42.7.10 -> 10.42.7.22:502 - 50% of responses are exceptions (illegal data address x20)

Persistent exceptions usually mean a supervision template polling addresses that no longer exist. Harmless in itself, it consumes cycles on the device and hides genuine faults in the logs.

### OT-009 - Devices disclose model and firmware to any peer

**Severity.** low
**Assets.** 10.42.7.21, 10.42.7.30
**References.** CR 1.2 / Mesure 1 (cartographie) / Mesure 20 (veille vulnérabilités)

Observed:

- 10.42.7.21: product=TM241CE40R, revision=5.1.9.9, vendor=Schneider Electric
- 10.42.7.30: article_number=6ES7 214-1AG40-0XB0, module_type=CPU 1214C DC/DC/DC, plc_name=LINE2_CPU

Identification cannot be turned off on these protocols, and it is useful to you as much as to an attacker. Use it: match each order number and firmware version against the CISA ICS advisories and the vendor bulletins, and record the result in the asset inventory.


## Method and limits

The capture was read offline. No frame was emitted towards the audited network,
so nothing in this report required interaction with a device in production.

What this implies for the reader: the report describes traffic seen during the
window above, and nothing else. A device that was silent does not appear. A
service that was not used does not appear. Absence of a finding is absence of
evidence, not evidence of absence, and the sections above should be read
alongside the configuration review and the interviews, never on their own.
