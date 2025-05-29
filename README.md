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
simad/
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


## 🛠️ Setup Instructions
1. **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/simad.git
    cd simad
    ```

2. **Start via Docker Compose (Dev Mode)**
    ```bash
    docker-compose up --build
    ```

3. **Access**
    - Frontend UI: [http://localhost:3000](http://localhost:3000)
    - API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
    - Elasticsearch: [http://localhost:9200](http://localhost:9200)

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

## 🧪 Testing
- **Run backend tests**
    ```bash
    cd backend
    pytest
    ```

- **Run frontend tests (React)**
    ```bash
    cd frontend
    npm run test
    ```

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

## 🙋 Contribution Guide
1. Fork this repo
2. Create a new branch (`feat/my-feature`)
3. Commit changes (`git commit -am 'Add feature'`)
4. Push to the branch (`git push origin feat/my-feature`)
5. Open a Pull Request

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

---

## Software Development Life Cycle (SDLC) Process for Future Features

### Phase 1: Planning & Requirements Gathering
- **Understand the Need**: Clearly articulate the problem or enhancement the new feature addresses.
- **Define Scope**: What exactly will the feature do? What won't it do (out of scope)?
- **Set Objectives**: What are the measurable goals for this feature? (e.g., "Reduce troubleshooting time by 10%").
- **Identify Stakeholders**: Who will use this feature? Who needs to approve it?
- **Gather Detailed Requirements**:
    - Functional Requirements: What inputs will it take? What outputs will it produce? What logic will it follow?
    - Non-Functional Requirements: Performance (how fast should it be?), Security (any new data handling?), Usability (ease of use), Reliability.
    - Data Source Identification: Identify the APIs (iLO, Orbit, Sirius) and data formats.
    - Success Criteria: How will you know if the feature is successful?

### Phase 2: Design
- **System Architecture Design**: How will the new feature integrate with the existing dashboard structure?
- **UI/UX Design**: Create wireframes or mockups.
- **Data Model Design**: Design new data structures.
- **API Integration Design**: Define API endpoints.

### Phase 3: Development
- **Modular Coding**: Organize code by function.
- **Incremental Development**: Build in small chunks.
- **Version Control**: Use Git, with frequent commits.
- **Error Handling**: Implement try-catch blocks.

### Phase 4: Testing
- **Unit Testing**: Test individual functions.
- **Integration Testing**: Verify different system parts work together.
- **Functional Testing**: Ensure the feature meets requirements.
- **Performance Testing**: Assess the impact on speed.
- **User Acceptance Testing (UAT)**: Gather end-user feedback.

### Phase 5: Deployment
- **Deployment to Server**: Upload updated files.
- **Rollback Plan**: Revert to previous version if needed.

### Phase 6: Maintenance & Monitoring
- **Monitor Performance**: Continuously monitor the dashboard's performance.
- **Bug Fixing**: Address any issues.
- **User Feedback**: Collect feedback and improve.

---