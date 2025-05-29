# 🖥️ VigilSiddhi - Scalable Infrastructure Monitoring and Alarm Dashboard
A real-time, scalable, and fault-tolerant monitoring system for server hardware (iLO, iDRAC, SNMP devices). This system visualizes infrastructure status using a color-coded dashboard and supports real-time alarms, device grouping, filtering, and historical trend analysis.

## 📌 Features
- ✅ Real-time status updates from multiple device types (iLO, iDRAC, SNMP)
- ✅ Color-coded blocks for device health (Red, Yellow, Green, Blue)
- ✅ Grouping of devices (e.g., by rack, region, project)
- ✅ Real-time alarms & historical log viewer
- ✅ Filter by group, severity, time, and device type
- ✅ Backend powered by Elasticsearch
- ✅ Scalable microservices-based architecture
- ✅ Secure API with RBAC (Role-Based Access Control)
- ✅ Fault-tolerant ingestion via Kafka or Redis
- ✅ RESTful APIs + WebSocket support

## 🧱 System Architecture
SNMP / iLO / iDRAC ─────► Ingestion Agents ─────► Kafka/Redis ─────► Processor ─────► Elasticsearch
▲
│
FastAPI Backend ─────► React/Vue Dashboard


- **Elasticsearch** stores all logs, status, and alarms
- **FastAPI** provides REST APIs for UI and data aggregation
- **React/Vue** frontend displays device/group blocks and alarms
- **WebSocket** or polling used for real-time updates

## ⚙️ Tech Stack
### Layer | Tech
- **Frontend**: React / Vue / Svelte + WebSocket
- **API Backend**: FastAPI (Python)
- **Data Pipeline**: Kafka / Redis Streams
- **Ingestion Agents**: Python (SNMP TrapD, REST Clients)
- **Database**: Elasticsearch
- **Deployment**: Docker, Kubernetes (optional)
- **CI/CD**: GitHub Actions / Jenkins
- **Security**: OAuth2 / API Key / RBAC

## 🗂️ Directory Structure
VigilSiddhi/
├── backend/ # FastAPI backend service
│ ├── main.py
│ ├── models/
│ ├── routers/
├── frontend/ # React/Vue frontend
│ ├── src/
├── ingestion/ # Ingestion scripts (e.g., SNMP, iLO polling)
│ ├── snmp_trap_listener.py
│ ├── ilo_poller.py
├── processor/ # Processing and data normalization
│ ├── normalizer.py
│ ├── push_to_elastic.py
├── elastic/ # Elasticsearch configurations
│ ├── index_mapping.json
├── docker-compose.yml # Docker Compose for local dev
└── README.md


## 🔌 API Overview (FastAPI)

| Endpoint                       | Method | Description                                   |
|---------------------------------|--------|-----------------------------------------------|
| `/api/devices`                  | GET    | List all devices with current status          |
| `/api/groups`                   | GET    | List all groups & aggregate status            |
| `/api/alarms?filter=active`     | GET    | Show active alarms                            |
| `/api/alarms?start=...&end=...` | GET    | Show alarms in time range                     |
| `/api/group/{id}`               | GET    | Detail view of group                          |

## 🔔 Alarm Color Codes

| Severity | Color | Description          |
|----------|-------|----------------------|
| Critical | 🔴 Red | Immediate attention  |
| Warning  | 🟡 Yellow | Performance degraded |
| OK       | 🟢 Green | Healthy              |
| Info     | 🔵 Blue | Informational status |

## 🔐 Security (Planned Features)
- JWT/OAuth2 authentication
- Role-based access for admin, viewer
- Rate limiting and input sanitization

## 📈 Roadmap
- Elasticsearch data storage
- Real-time ingestion pipeline
- UI with real-time update
- Alarm filtering
- SMS/Email/Slack integration
- Export to CSV, PDF
- Custom alert rules per group


## 📚 Learn Through This Project
- REST API development (FastAPI)
- SNMP / API ingestion pipelines
- Real-time dashboards (WebSocket)
- Elasticsearch queries & mapping
- CI/CD setup (GitHub Actions, Docker)
- DevOps lifecycle using microservices
- Monitoring system design

## 📞 Contact
- Maintainer: **Prashant Kadam**
- 📧 pdek1991@gmail.com

