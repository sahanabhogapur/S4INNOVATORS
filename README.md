# Task Management Dashboard

A full-stack task management application with interactive analytics and real-time updates.

## Features

- User authentication (register/login)
- Task management (create, read, update, delete)
- Interactive dashboard with charts and statistics
- Real-time task status updates
- Priority-based task organization
- Responsive design for all devices

## Tech Stack

### Frontend
- React with TypeScript
- Material-UI for components
- Recharts for interactive charts
- React Router for navigation
- Axios for API calls

### Backend
- Node.js with Express
- MongoDB with Mongoose
- JWT for authentication
- Winston for logging
- Swagger for API documentation

## Getting Started

### Prerequisites
- Node.js (>=14.0.0)
- MongoDB
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd task-management-dashboard
```

2. Install dependencies:
```bash
# Install server dependencies
npm install

# Install client dependencies
cd client
npm install
```

3. Create a `.env` file in the root directory with the following variables:
```
PORT=3000
MONGODB_URI=mongodb://localhost:27017/task-management
JWT_SECRET=your-super-secret-key-change-this-in-production
NODE_ENV=development
```

4. Start the development servers:
```bash
# Start the backend server
npm run dev

# In a new terminal, start the frontend server
cd client
npm start
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:3000/api
- API Documentation: http://localhost:3000/api-docs

## API Documentation

The API documentation is available through Swagger UI at `/api-docs`. It provides detailed information about all available endpoints, request/response formats, and authentication requirements.

## Project Structure

```
task-management-dashboard/
├── client/                 # React frontend
│   ├── public/            # Static files
│   │   ├── components/    # Reusable components
│   │   ├── contexts/      # React contexts
│   │   ├── pages/         # Page components
│   │   └── App.tsx        # Main App component
│   └── package.json       # Frontend dependencies
├── server.js              # Backend server
├── swagger.yaml           # API documentation
├── .env                   # Environment variables
└── package.json           # Backend dependencies
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License. 