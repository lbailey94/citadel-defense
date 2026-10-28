# Practice report status

The October 26, 2026 practice report is withdrawn as a security-assurance claim.
Its `100/100` score and `BATTLE-TESTED · AUDIT-READY` verdict combined real
operations with Python simulations and assigned constants. They do not establish
an independent audit or production readiness.

The unchanged historical report is recoverable from base commit
`e1a8f10e54a0ba7ce298e287be36cc71a70f948f` at this path. Its exact bytes and SHA-256,
and the original generator, were also preserved in the October 26 parent review
packet before replacement. See [AUDIT_SCOPE.md](AUDIT_SCOPE.md) for the concrete
claim corrections and remaining review work.

Generate fresh, scoped JSON and Markdown reports with:

```bash
python3 defense/practice_audit_battery.py --checks bend --output-dir /tmp/citadel-internal-checks
```

Bend checks Bool/Nat lemmas and synthetic arithmetic folds. Missing or failed
checks remain visible, and no composite security score is generated. Add the
separate CPR agreement selection only after building and pinning its three
engines as described in the [README](../README.md).
