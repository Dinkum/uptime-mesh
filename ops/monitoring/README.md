# UptimeMesh Observability Stack (M7)

This folder contains baseline config for:

- Prometheus scrape + alert rules
- Alertmanager routing
- Grafana provisioning (Prometheus datasource + dashboard provider)

These files are source-first and can be copied onto core nodes.

## Expected endpoints

- App metrics: `http://127.0.0.1:8010/metrics`
- Node exporter: `127.0.0.1:9100`

Adjust targets before production rollout.

## Quick start (manual)

1. Install Prometheus, Alertmanager, and Grafana on a core node.
2. Copy configs from this folder:
   - `prometheus.yml`
   - `alert_rules.yml`
   - `alertmanager.yml`
   - `grafana/provisioning/*`
3. Load dashboard JSON from `grafana/dashboards/uptimemesh-overview.json`.
4. Start services and confirm:
   - Prometheus target `uptimemesh` is `UP`
   - `/metrics` has data
   - Grafana dashboard renders counters/latency
