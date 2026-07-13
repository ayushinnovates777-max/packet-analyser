# PacketLens AI

A professional, modern web application for PCAP analysis and threat detection.

## Phase 1 (MVP) Features
- Modern SOC-style dark theme dashboard
- Secure PCAP/PCAPNG upload with validation
- Heuristic-based basic threat detection (e.g., Port Scans)
- Protocol distribution and traffic statistics
- Responsive charts and UI

## Technology Stack
- **Frontend**: React, TypeScript, Vite, Tailwind CSS, Framer Motion, Chart.js
- **Backend**: Python, FastAPI, PyShark
- **Infrastructure**: Docker & Docker Compose

## Quick Start (Docker)

1. Make sure Docker and Docker Compose are installed.
2. Run the application:
   ```bash
   docker-compose up --build
   ```
3. Access the Frontend at `http://localhost:5173`
4. Access the Backend API Docs at `http://localhost:8000/docs`

## Local Development

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
# Requires tshark to be installed on your system
uvicorn app.main:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## Security & Architecture Notes
- Uploads are validated by checking MIME types and magic bytes.
- Maximum upload size is restricted.
- PyShark parses packets in an asyncio loop.
- Designed with modularity for future threat intelligence and AI integrations.
