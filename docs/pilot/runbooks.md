# Operational Runbooks

## Incident: Connector failure
1. Check `/v1/connectors/status`
2. Review `connector_runs` and job errors
3. Re-run sync endpoint
4. Enable simulated fallback if external dependency is down

## Incident: Failed remediation action
1. Inspect approval count and policy requirement
2. Simulate action impact
3. Execute with approver role
4. Rollback if impact exceeds threshold
