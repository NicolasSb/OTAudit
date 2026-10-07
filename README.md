# otaudit

Reads a capture of industrial traffic and produces an asset inventory and an
audit report, with findings mapped to IEC 62443-4-2 component requirements and
to the ANSSI classification measures.

It is passive. It opens a pcap file and nothing else: no scanning, no probing,
no connection to anything. On a site with a running process, that is usually
the only thing an operator will authorise on a running process, and it is
enough to answer the first questions of an audit: what is actually on this
network, who talks to whom, and who is allowed to write.

## What it does not do

- No active probing. Identification is only read from frames that happen to be
  in the capture.
- No vulnerability database. The report gives you order numbers and firmware
  strings; matching them against CISA ICS advisories is your job.
- No risk analysis. The EBIOS RM export is a scaffold with empty severity and
  likelihood fields, because a capture cannot tell you what the process does.
- Modbus/TCP and S7comm only. Not DNP3, not EtherNet/IP, not OPC UA, not
  Profinet. Serial Modbus is out of reach by construction.

## Install

    pip install .

Python 3.11 or later. Three runtime dependencies: pydantic, PyYAML, Jinja2.

## Use

Write a scope file first. The tool refuses to run without one, because a
capture with no record of who authorised it is not evidence you can put in a
report.

```yaml
engagement: "Passive audit - Site A control network"
authorized_by: "J. Martin, maintenance manager"
reference: "BC-2026-014"
window:
  start: "2023-11-14T20:00:00+00:00"
  end: "2023-11-15T02:00:00+00:00"
targets:
  - 10.42.7.0/26
exclusions:
  - 10.42.7.13/32   # fire safety PLC, out of scope by agreement
```

Check it, then run the analysis:

    otaudit check-scope scope.yaml
    otaudit analyse capture.pcap --scope scope.yaml \
        --report report.md --json inventory.json --ebios ebios.json

Without `--report`, the Markdown goes to standard output. `--fail-on high`
exits with status 3 when a finding reaches that severity, which is what you
want if this ever runs unattended.

A sample capture is included so you can see the output before you have a real
one:

    python scripts/make_sample.py
    otaudit analyse samples/demo.pcap --scope samples/scope.yaml

## Rules

| Id | Finding | Default severity |
| --- | --- | --- |
| OT-001 | Control traffic without authentication or integrity protection | medium |
| OT-002 | Write operations observed | medium |
| OT-003 | Several hosts write to the same device | high |
| OT-004 | CPU control services invoked | high |
| OT-005 | Industrial hosts outside the declared target ranges | medium |
| OT-006 | Traffic captured from an excluded host | high |
| OT-007 | Recurrent protocol exceptions | low |
| OT-008 | Legacy management services on the control segment | medium or high |
| OT-009 | Devices disclose model and firmware | low |
| OT-010 | Unstable polling intervals | info |
| OT-011 | Capture outside the authorised window | medium |

Severities are defaults for a capture read in isolation. They are a starting
point for the discussion with the integrator, not a verdict: whether a second
writing master is a finding or the documented architecture is something only
the operator can say.

Rules live in `findings.py`, one function each, and the report template is a
Jinja file inside the package. Both are meant to be edited: the wording belongs
to whoever signs the report.

## Design notes

The capture is decoded in-house, from the pcap or pcapng header down to the
Modbus PDU, rather than through scapy or dpkt. The reason is practical: before
this runs on a client network, someone on the client side may want to read it,
and a few hundred lines of struct unpacking can be read in an afternoon.

TCP reassembly handles retransmissions and duplicates, and resynchronises on a
gap rather than splicing bytes that never followed each other. A mirrored port
under load drops frames, and a decoder that hides that produces an inventory
nobody should trust. Gaps and truncated records are counted and printed in the
report.

## Tests

    ./run_tests.sh

Creates a virtualenv in `.venv`, installs the dev extras, then runs ruff, mypy
in strict mode and pytest with coverage. Protocol decoding is tested against
literal frames written by hand, not against the frames the synthesis module
produces, so a mistake in the builders cannot make a broken decoder look
correct.

## Licence

MIT.
