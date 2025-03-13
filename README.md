# O-Saver

## Introduction
**O-Saver** is a mobile application designed to automate the traditional African "Ajo" savings system. It enables contributors to save money daily, weekly, or monthly under different agents (collectors) and track their contributions digitally. The system replaces manual bookkeeping with a seamless, automated process using **FastAPI for the backend** and **React Native for the frontend**.

## Features
### **For Contributors:**
- Register and manage savings with multiple agents.
- Track contributions in real-time (daily, weekly, monthly, yearly).
- Choose payment modes (Cash or Bank Transfer).
- Request withdrawals and view available balance.
- Get notifications when transactions are confirmed.

### **For Agents (Collectors):**
- Manage multiple contributors under their supervision.
- Issue unique savings cards per contributor.
- Record contributions and withdrawals.
- Approve or decline transfer payments and withdrawal requests.
- View total collections (daily, weekly, monthly, yearly).
- Access a financial dashboard with key metrics.

## Tech Stack
- **Frontend:** React Native (for cross-platform mobile development)
- **Backend:** FastAPI (high-performance Python web framework)
- **Database:** PostgreSQL (relational database for structured data)
- **Authentication:** JWT (JSON Web Tokens for secure user authentication)
- **Notifications:** Firebase Cloud Messaging (for push notifications)

## Installation Guide
### **Backend (FastAPI)**
1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/o-saver.git
   cd o-saver/backend
   ```
2. Create and activate a virtual environment:
   ```sh
   python -m venv env
   source env/bin/activate   # On Windows use: env\Scripts\activate
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
4. Run the server:
   ```sh
   uvicorn main:app --reload
   ```
5. The API will be available at `http://127.0.0.1:8000`

### **Frontend (React Native)**
1. Navigate to the frontend directory:
   ```sh
   cd ../frontend
   ```
2. Install dependencies:
   ```sh
   npm install
   ```
3. Run the development server:
   ```sh
   npm run android  # For Android
   npm run ios      # For iOS (requires MacOS)
   ```

## API Endpoints
### **Authentication**
- `POST /auth/signup` - Register a new user
- `POST /auth/login` - User login and token generation

### **Contributors**
- `GET /contributors/{id}` - Get contributor details
- `POST /contributors/save` - Save money with an agent
- `POST /contributors/withdraw` - Request a withdrawal

### **Agents**
- `GET /agents/{id}/contributors` - Get all contributors under an agent
- `POST /agents/confirm-payment` - Confirm a contributor's payment
- `GET /agents/dashboard` - View financial summary

## Future Improvements
- Implement AI-based savings recommendations
- Multi-language support
- Agent commission tracking system

## License
This project is licensed under the **MIT License**.

---
### Contributors
- **Backend:**  (FastAPI)
- **Frontend:**  (React Native)
- **UI/UX:** [Your Name]


