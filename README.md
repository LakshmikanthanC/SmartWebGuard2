# SmartWebGuard

SmartWebGuard is a comprehensive cybersecurity platform designed to detect and analyze network threats, including URL-based malware, phishing attempts, and network intrusion detection. The system combines machine learning models with real-time monitoring to provide actionable insights for network security.

## Features

- **URL Analysis**: Deep scanning of URLs for malware, phishing, and viruses
- **Network Intrusion Detection**: ML-powered prediction of network attacks using CNN models
- **Real-time Dashboard**: Live monitoring with charts, alerts, and threat visualization
- **Alert Management**: Comprehensive alert system with severity levels and detailed analysis
- **Analytics**: Timeline charts, severity heatmaps, and protocol breakdowns
- **Batch Processing**: Scan multiple URLs simultaneously
- **RESTful API**: Full API support for integration with other security tools

## Architecture

The project consists of three main components:

### AI Engine (Python/Flask)
- Machine learning models for threat detection
- URL analysis and scanning capabilities
- Network intrusion detection system (NIDS)
- REST API endpoints for predictions and scans

### Backend (Node.js/Express)
- MongoDB database integration
- WebSocket support for real-time updates
- API routes for alerts, analytics, and predictions
- Socket.io for live data streaming

### Frontend (React)
- Modern web interface with responsive design
- Real-time dashboard with interactive charts
- URL scanning interface
- Alert management and analytics visualization

## Tech Stack

- **Frontend**: React 18, Chart.js, Socket.io-client, Axios
- **Backend**: Node.js, Express.js, MongoDB, Socket.io
- **AI Engine**: Python, Flask, TensorFlow, Scikit-learn, Pandas
- **Database**: MongoDB
- **Deployment**: Docker-ready architecture

## Installation

### Prerequisites
- Node.js (v16+)
- Python (v3.8+)
- MongoDB
- npm or yarn

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd broo
   ```

2. **Setup AI Engine**
   ```bash
   cd ai-engine
   pip install -r requirements.txt
   python app.py
   ```

3. **Setup Backend**
   ```bash
   cd ../backend
   npm install
   # Configure MongoDB connection in config/db.js
   npm start
   ```

4. **Setup Frontend**
   ```bash
   cd ../frontend/hi
   npm install
   npm start
   ```

5. **Database Setup**
   ```bash
   cd ../../scripts
   node seed_db.js
   ```

## API Endpoints

### AI Engine (Port 5000)

#### URL Scanning
- `POST /api/url/scan` - Deep scan a single URL
- `POST /api/url/quick` - Quick pattern analysis
- `POST /api/url/batch` - Scan multiple URLs

#### Prediction
- `POST /api/predict` - Network intrusion detection prediction
- `GET /api/health` - Health check

### Backend (Port 3001)

#### Alerts
- `GET /api/alerts` - Get all alerts
- `POST /api/alerts` - Create new alert
- `PUT /api/alerts/:id` - Update alert
- `DELETE /api/alerts/:id` - Delete alert

#### Analytics
- `GET /api/analytics/timeline` - Timeline data
- `GET /api/analytics/severity` - Severity breakdown
- `GET /api/analytics/protocol` - Protocol statistics

#### URL Scan
- `POST /api/urlscan` - Scan URL through backend
- `GET /api/urlscan/history` - Scan history

## Usage

### Starting the Application

1. Start MongoDB
2. Start AI Engine: `cd ai-engine && python app.py`
3. Start Backend: `cd backend && npm start`
4. Start Frontend: `cd frontend/hi && npm start`

Access the application at `http://localhost:3000`

### URL Scanning

Use the URL Scanner component to analyze suspicious URLs:

```javascript
// Example API call
const response = await axios.post('http://localhost:5000/api/url/scan', {
  url: 'https://suspicious-site.com',
  deep_scan: true
});
```

### Network Prediction

Send network traffic features for intrusion detection:

```javascript
const prediction = await axios.post('http://localhost:5000/api/predict', {
  features: {
    duration: 0.5,
    protocol_type: 'tcp',
    service: 'http',
    // ... other features
  }
});
```

## Configuration

### AI Engine
- Model files stored in `ai-engine/models/`
- Configuration in `ai-engine/config.py`
- Requirements in `requirements.txt`

### Backend
- Database config in `backend/config/db.js`
- Routes in `backend/routes/`
- Models in `backend/models/`

### Frontend
- API base URL configured in `frontend/hi/src/services/api.js`
- Socket connection in `frontend/hi/src/context/SocketContext.js`

## Development

### Running Tests
```bash
# AI Engine tests
cd ai-engine && python -m pytest

# Backend tests
cd backend && npm test

# Frontend tests
cd frontend/hi && npm test
```

### Building for Production
```bash
# Frontend build
cd frontend/hi && npm run build

# Backend build (if using PM2 or similar)
cd backend && npm run build
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

This tool is designed for security research and defensive purposes only. Users are responsible for complying with applicable laws and regulations when using this software.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation in `/docs`
- Contact the development team

---

**Version**: 2.0.0
**Last Updated**: 2026

