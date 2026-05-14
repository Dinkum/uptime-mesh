# UptimeMesh Observability Stack (M7)

This folder contains baseline config for:

- Prometheus scrape + alert rules
- Alertmanager routing
- Grafana provisioning (Prometheus datasource + dashboard provider)

These files are source-first bootstrap examples. At runtime, UptimeMesh can render Prometheus config from live node registry state and monitoring settings, then validate, apply, reload, and roll back through `RuntimeController`.

## Expected endpoints

- App metrics: `http://127.0.0.1:8010/metrics`
- Node exporter: `127.0.0.1:9100`

When `RUNTIME_MONITORING_ENABLE=true`, the generated Prometheus config is written to `RUNTIME_MONITORING_PROMETHEUS_CONFIG_PATH` and visible through the monitoring API/UI. Hand edits to generated files can be replaced by the next runtime reconcile.

## Quick start (manual)

1. Install Prometheus, Alertmanager, and Grafana on a core node.
2. Copy baseline configs from this folder:
   - `prometheus.yml`
   - `alert_rules.yml`
   - `alertmanager.yml`
   - `grafana/provisioning/*`
3. Load dashboard JSON from `grafana/dashboards/uptimemesh-overview.json`.
4. Start services and confirm:
   - Prometheus target `uptimemesh` is `UP`
   - `/metrics` has data
   - Grafana dashboard renders counters/latency

## Runtime generated config

- Enable with `RUNTIME_MONITORING_ENABLE=true`.
- Main output: `RUNTIME_MONITORING_PROMETHEUS_CONFIG_PATH`.
- Candidate and rollback paths: `RUNTIME_MONITORING_PROMETHEUS_CANDIDATE_PATH`, `RUNTIME_MONITORING_PROMETHEUS_BACKUP_PATH`.
- Validation and reload commands: `RUNTIME_MONITORING_VALIDATE_COMMAND`, `RUNTIME_MONITORING_RELOAD_COMMAND`.
- API surface: `/monitoring/status`, `/monitoring/prometheus/config`.
