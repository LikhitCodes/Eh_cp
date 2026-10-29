# API Sentinel Pilot Deployment Guide

## Goal
Deploy API Sentinel in a bank-controlled environment with Kong, GitHub integration, and Splunk enrichment.

## Prerequisites
- Docker + Docker Compose
- Network access to gateway and SIEM APIs
- Keycloak admin access

## Steps
1. Configure `.env.launch` values.
2. Run `make launch`.
3. Verify health at `/v1/health` and `/metrics`.
4. Sync connectors via `/v1/connectors/*/sync`.
5. Seed deterministic demo via `/v1/demo/seed` if needed.

## Rollback
- Stop services: `make launch-down`
- Restore DB from backup script if required.
