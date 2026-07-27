# OpenList Secure Platform

> A risk-based security assessment and management platform for OpenList-based self-hosted file systems.

## Overview

OpenList Secure Platform is a prototype security management system designed to improve the security visibility of OpenList deployments. Rather than replacing OpenList, the platform provides an additional security management layer that evaluates configuration risks, processes security events, generates alerts, records audit activities, and visualizes security posture through an interactive dashboard.

The project was developed as a Final Year Project (FYP) focusing on practical security management for self-hosted file systems.

---

## Features

### Configuration Security Assessment

- Analyze OpenList-related configuration files
- Detect predefined security misconfigurations
- Generate structured security findings
- Provide evidence and remediation recommendations

### Risk Scoring

- Severity-based scoring model
- Transparent penalty calculation
- Overall security score generation
- Risk level classification

### Security Event Processing

- Import and parse security log files
- Convert logs into structured events
- Categorize security activities
- Store event history

### Policy-Based Alerting

- Configurable policy thresholds
- Low security score alerts
- Repeated login failure detection
- Long token validity alerts
- Critical configuration notifications

### API Audit Logging

- Record administrative API activities
- Authorized and unauthorized request tracking
- Persistent audit records
- Request history review

### Dashboard Visualization

- Security overview
- Scan history
- Risk trends
- Event statistics
- Alert summaries
- Audit information

---

## System Architecture

```
                 OpenList Configuration
                         +
                    Security Logs
                         │
                  OpenList Adapter
                         │
                Security Management Core
      ┌──────────────┬──────────────┬──────────────┐
      │              │              │              │
 Configuration   Risk Scoring   Event Engine   Alert Engine
      │              │              │              │
      └──────────────┴──────────────┴──────────────┘
                         │
                     SQLite Database
                         │
                     RESTful API
                         │
                  React Dashboard
```

---

## Technology Stack

### Backend

- Go
- Gin
- SQLite

### Frontend

- React
- TypeScript
- Vite

### Security

- REST API
- API Key Authentication
- Audit Logging
- Policy Engine

---

## Project Structure

```
.
├── cmd/
├── internal/
│   ├── adapters/
│   ├── core/
│   ├── api/
│   ├── storage/
│   └── services/
├── frontend/
├── evaluation/
├── migrations/
└── docs/
```

---

## Security Workflow

```
Configuration / Logs
        │
        ▼
   Structured Analysis
        │
        ▼
  Security Findings
        │
        ▼
   Risk Score Calculation
        │
        ▼
 Policy Evaluation
        │
        ▼
 Alerts & Audit Logs
        │
        ▼
 Dashboard Visualization
```

---

## Current Capabilities

The current prototype supports:

- Configuration security assessment
- Structured security findings
- Severity-based risk scoring
- Security event import
- Policy-driven alert generation
- API key protection
- Administrative audit logging
- Dashboard visualization
- Historical scan records

---

## Project Scope

The current implementation focuses on representative OpenList-related security scenarios.

It evaluates:

- Authentication configuration
- HTTPS settings
- Protocol exposure
- Logging configuration
- Token validity
- Selected operational security events

The platform does **not** perform:

- Static source-code analysis
- Malware detection
- Penetration testing
- Real-time intrusion detection
- Full vulnerability scanning

---

## Future Improvements

Potential future work includes:

- Live OpenList integration
- Expanded security rule library
- Role-Based Access Control (RBAC)
- Real-time log monitoring
- Support for additional self-hosted platforms
- Advanced risk scoring models
- Production-grade authentication
- PostgreSQL support

---

## Research Context

This project was developed as an undergraduate Final Year Project.

The research focuses on designing and implementing a security management workflow that integrates:

- Configuration assessment
- Risk scoring
- Event processing
- Alert generation
- Audit logging
- Dashboard visualization

rather than proposing a new vulnerability detection algorithm.

---

## License

This project is provided for educational and research purposes.
