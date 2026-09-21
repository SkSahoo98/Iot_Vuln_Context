# Lab safety and scope

This project is defensive. It exists to assess **your** lab, not other people's networks.

## Allowed

- Devices you own
- An isolated IoT lab
- Systems with explicit written authorization

## Not allowed

- Scanning campus, ISP, cloud, or neighbour networks
- Using this scanner against arbitrary public IPs
- Publishing default MQTT credentials to the internet
- Treating an open port as a "hack" without evidence

## Lab-only marker

Any active check (port probe, MQTT connect, TLS probe) must be documented as **authorized lab-only** in the finding and in `EXPERIMENT_LOG.md`.

## Evidence rule

Every finding needs: Finding, Evidence, Severity, Confidence, Affected asset, Detection method, Reason, Potential impact, Remediation, References, Timestamp.
