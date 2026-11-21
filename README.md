# Ta'meer-e-Rekhta - Backend API

The Node.js & Express backend API powering the Ta'meer-e-Rekhta website and Management Portal.

## 🚀 Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB Atlas via Mongoose
- **Authentication**: JWT (JSON Web Tokens) & Bcrypt
- **Email Service**: Nodemailer (SMTP)
- **Integrations**: Google Sheets & Google Drive API (Google APIs client library)

## 📁 Project Structure

```text
├── scripts/
│   ├── google-apps-script-setup.js   # Script for Google Apps Script sync setup
│   └── verify-backend.js             # Diagnostic and test script
├── src/
│   ├── config/
│   │   └── db.js                     # MongoDB connection
│   ├── middleware/
│   │   └── auth.js                   # JWT authentication middleware
│   ├── models/                       # Mongoose data models
│   │   ├── Application.js
│   │   ├── AuditLog.js
│   │   ├── ContactInquiry.js
│   │   ├── Department.js
│   │   ├── Donation.js
│   │   ├── Event.js
│   │   ├── EventRegistration.js
│   │   ├── MediaAsset.js
│   │   ├── Notification.js
│   │   ├── Task.js
│   │   └── User.js
│   ├── routes/                       # Express route controllers
│   │   ├── auth.routes.js
│   │   ├── contact.routes.js
│   │   ├── donate.routes.js
│   │   ├── events.routes.js
│   │   ├── gallery.routes.js
│   │   ├── media.routes.js
│   │   ├── portal.routes.js
│   │   └── volunteer.routes.js
│   ├── services/                     # External services
│   │   ├── email.service.js
│   │   ├── googleDrive.service.js
│   │   └── sheets.service.js
│   └── server.js                     # Application entry point
├── .env.example                      # Environment variables template
├── .gitignore
├── package.json
└── package-lock.json
```

## 🛠️ Setup Instructions

### 1. Prerequisites
- Node.js (v18+ recommended)
- MongoDB Atlas cluster or local MongoDB instance

### 2. Installation
```bash
npm install
```

### 3. Environment Variables
Copy `.env.example` to `.env` and fill in your credentials:
```bash
cp .env.example .env
```

### 4. Running the Server
- **Development mode (with auto-reload)**:
  ```bash
  npm run dev
  ```
- **Production mode**:
  ```bash
  npm start
  ```
- **Verification script**:
  ```bash
  npm test
  ```

## 📡 API Endpoints Summary

- **Health Check**: `GET /api/health`
- **Auth**: `/api/auth` (Register, Login, Refresh, Password Management)
- **Volunteer**: `/api/volunteer` (Volunteer application submission & verification)
- **Donation**: `/api/donate` (Donations & receipts)
- **Contact**: `/api/contact` (Contact inquiries)
- **Events**: `/api/events` (Events & registration)
- **Media**: `/api/media` (Media assets management)
- **Gallery**: `/api/gallery` (Photo/video gallery)
- **Portal**: `/api/*` (Super Admin, HR, Department & Member routes)
