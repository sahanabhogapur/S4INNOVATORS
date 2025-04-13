// Load environment variables first
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const path = require('path');
const morgan = require('morgan');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const { createLogger, format, transports } = require('winston');
const { performance } = require('perf_hooks');
const cache = require('memory-cache');
const os = require('os');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mockBudgetData = require('./mockData/budgetData');

// Import models
const { User, Task } = require('./models');

// Define Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['income', 'expense'], required: true },
  amount: { type: Number, required: true },
  category: { type: String, required: true },
  description: { type: String },
  date: { type: Date, default: Date.now },
  recurring: { type: Boolean, default: false }
});

// Register the Transaction model
const Transaction = mongoose.model('Transaction', transactionSchema);

// Initialize Winston logger
const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.File({ filename: 'combined.log' }),
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    })
  ]
});

// Load Swagger documentation
const swaggerDocument = YAML.load('./swagger.yaml');

// Import routes
const authRoutes = require('./routes/auth');
const budgetRoutes = require('./routes/budget');
const aiRoutes = require('./routes/ai');

// Validate environment variables
const validateEnv = () => {
  const requiredEnvVars = ['OPENAI_API_KEY', 'MONGODB_URI', 'JWT_SECRET'];
  const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

  if (missingEnvVars.length > 0) {
    logger.error('Missing required environment variables:', missingEnvVars);
    process.exit(1);
  }

  logger.info('✅ Environment variables validated successfully');
};

// Performance monitoring middleware
const performanceMonitor = (req, res, next) => {
  const start = performance.now();
  res.on('finish', () => {
    const duration = performance.now() - start;
    logger.info(`${req.method} ${req.url} - ${duration.toFixed(2)}ms`);
    cache.put(`${req.method}-${req.url}`, {
      duration,
      timestamp: new Date().toISOString()
    });
  });
  next();
};

// Create Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"]
    },
  },
}));

// Compression middleware with custom options
app.use(compression({
  level: 6,
  threshold: 100 * 1024, // Only compress responses larger than 100KB
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// Rate limiting with different rules for different routes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later'
});

// Logging middleware with custom format
app.use(morgan(':method :url :status :response-time ms - :res[content-length]', {
  stream: {
    write: message => logger.info(message.trim())
  }
}));

// CORS configuration with enhanced security
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 600
};
app.use(cors(corsOptions));

// Body parsing middleware with size limits
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb',
  parameterLimit: 1000
}));

// Static files with cache control
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  maxAge: '1d',
  etag: true,
  lastModified: true
}));

// API Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Performance monitoring
app.use(performanceMonitor);

// Database connection with advanced retry logic
const connectWithRetry = async () => {
  const maxRetries = 5;
  let retryCount = 0;
  let lastError = null;

  const connect = async () => {
    try {
      logger.info(`🔄 Attempting MongoDB connection (Attempt ${retryCount + 1}/${maxRetries})`);
      
      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
        minPoolSize: 5,
        connectTimeoutMS: 10000,
        heartbeatFrequencyMS: 2000
      });
      
      logger.info('✅ MongoDB connected successfully');
      
      mongoose.connection.on('error', (err) => {
        logger.error('❌ MongoDB connection error:', err);
        lastError = err;
      });

      mongoose.connection.on('disconnected', () => {
        logger.warn('⚠️ MongoDB disconnected');
        if (retryCount < maxRetries) {
          retryCount++;
          setTimeout(connect, Math.min(1000 * Math.pow(2, retryCount), 30000));
        } else {
          logger.error('❌ Maximum retry attempts reached');
          process.exit(1);
        }
      });

      mongoose.connection.on('reconnected', () => {
        logger.info('✅ MongoDB reconnected');
        retryCount = 0;
        lastError = null;
      });

    } catch (err) {
      logger.error('❌ MongoDB connection error:', err);
      lastError = err;
      if (retryCount < maxRetries) {
        retryCount++;
        const delay = Math.min(1000 * Math.pow(2, retryCount), 30000);
        logger.info(`⏳ Retrying in ${delay/1000} seconds... (${retryCount}/${maxRetries})`);
        setTimeout(connect, delay);
      } else {
        logger.error('❌ Maximum retry attempts reached');
        process.exit(1);
      }
    }
  };

  await connect();
};

// Routes with rate limiting
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/budget', apiLimiter, budgetRoutes);
app.use('/api/ai', apiLimiter, aiRoutes);

// Mock budget routes for development
app.get('/api/budget/:userId', (req, res) => {
  try {
    const userId = req.params.userId;
    const userTransactions = mockBudgetData.filter(t => t.userId === userId);
    res.json(userTransactions);
  } catch (error) {
    logger.error('Error fetching budget data:', error);
    res.status(500).json({ error: 'Failed to fetch budget data' });
  }
});

app.get('/api/budget/:userId/category-summary', (req, res) => {
  try {
    const userId = req.params.userId;
    const userTransactions = mockBudgetData.filter(t => t.userId === userId);
    
    const categorySummary = userTransactions.reduce((acc, transaction) => {
      if (transaction.type === 'expense') {
        if (!acc[transaction.category]) {
          acc[transaction.category] = {
            total: 0,
            count: 0,
            average: 0
          };
        }
        acc[transaction.category].total += transaction.amount;
        acc[transaction.category].count += 1;
        acc[transaction.category].average = acc[transaction.category].total / acc[transaction.category].count;
      }
      return acc;
    }, {});

    res.json(categorySummary);
  } catch (error) {
    logger.error('Error fetching category summary:', error);
    res.status(500).json({ error: 'Failed to fetch category summary' });
  }
});

app.get('/api/budget/:userId/monthly-summary', (req, res) => {
  try {
    const userId = req.params.userId;
    const userTransactions = mockBudgetData.filter(t => t.userId === userId);
    
    const monthlySummary = userTransactions.reduce((acc, transaction) => {
      const month = new Date(transaction.date).toLocaleString('default', { month: 'long' });
      if (!acc[month]) {
        acc[month] = {
          income: 0,
          expenses: 0,
          savings: 0
        };
      }
      
      if (transaction.type === 'income') {
        acc[month].income += transaction.amount;
      } else if (transaction.type === 'expense') {
        acc[month].expenses += transaction.amount;
      }
      
      acc[month].savings = acc[month].income - acc[month].expenses;
      return acc;
    }, {});

    res.json(monthlySummary);
  } catch (error) {
    logger.error('Error fetching monthly summary:', error);
    res.status(500).json({ error: 'Failed to fetch monthly summary' });
  }
});

app.get('/api/budget/:userId/recommendations', (req, res) => {
  try {
    const userId = req.params.userId;
    const userTransactions = mockBudgetData.filter(t => t.userId === userId);
    
    const recommendations = [];
    
    // Analyze spending patterns
    const categorySummary = userTransactions.reduce((acc, transaction) => {
      if (transaction.type === 'expense') {
        if (!acc[transaction.category]) {
          acc[transaction.category] = 0;
        }
        acc[transaction.category] += transaction.amount;
      }
      return acc;
    }, {});

    // Generate recommendations based on spending patterns
    if (categorySummary['Utilities'] > 400) {
      recommendations.push('Your utility bills seem high. Consider energy-saving measures.');
    }
    
    if (categorySummary['Groceries'] > 300) {
      recommendations.push('Your grocery spending is above average. Try meal planning to reduce costs.');
    }
    
    if (categorySummary['Housing'] > 1500) {
      recommendations.push('Housing costs are significant. Consider finding a more affordable place or getting a roommate.');
    }

    res.json(recommendations);
  } catch (error) {
    logger.error('Error generating recommendations:', error);
    res.status(500).json({ error: 'Failed to generate recommendations' });
  }
});

// Health check with detailed system information
app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      total: os.totalmem(),
      free: os.freemem(),
      used: os.totalmem() - os.freemem()
    },
    cpu: {
      load: os.loadavg()
    },
    database: {
      status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      lastError: mongoose.connection.lastError || null
    },
    system: {
      platform: process.platform,
      nodeVersion: process.version,
      environment: process.env.NODE_ENV || 'development'
    },
    cache: {
      size: cache.size(),
      keys: cache.keys()
    }
  };
  res.status(200).json(health);
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    // Create user
    const user = new User({
      username,
      email,
      password
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({ token, user: { id: user._id, username, email } });
  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({ message: 'Error creating user' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await user.comparePassword(password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Task routes
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.user.userId });
    res.json(tasks);
  } catch (error) {
    logger.error('Error fetching tasks:', error);
    res.status(500).json({ message: 'Error fetching tasks' });
  }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const task = new Task({
      ...req.body,
      userId: req.user.userId
    });
    await task.save();
    res.status(201).json(task);
  } catch (error) {
    logger.error('Error creating task:', error);
    res.status(500).json({ message: 'Error creating task' });
  }
});

app.get('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    res.json(task);
  } catch (error) {
    logger.error('Error fetching task:', error);
    res.status(500).json({ message: 'Error fetching task' });
  }
});

app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { ...req.body, updatedAt: new Date() },
      { new: true }
    );
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    res.json(task);
  } catch (error) {
    logger.error('Error updating task:', error);
    res.status(500).json({ message: 'Error updating task' });
  }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    res.status(204).send();
  } catch (error) {
    logger.error('Error deleting task:', error);
    res.status(500).json({ message: 'Error deleting task' });
  }
});

// Serve React app in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'client/build')));
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
  });
}

// Enhanced 404 handler
app.use((req, res) => {
  const requestedPath = req.url;
  const method = req.method;
  
  logger.warn(`404: ${method} ${requestedPath}`);
  
  res.status(404).json({
    error: 'Route not found',
    message: `The requested endpoint ${method} ${requestedPath} does not exist`,
    timestamp: new Date().toISOString(),
    request: {
      method,
      path: requestedPath,
      query: req.query,
      headers: req.headers
    },
    documentation: '/api-docs',
    suggestions: [
      'Check the API documentation at /api-docs',
      'Verify the HTTP method and URL path',
      'Ensure all required parameters are provided',
      'Check for typos in the endpoint'
    ]
  });
});

// Advanced error handling
app.use((err, req, res, next) => {
  logger.error('Error:', {
    message: err.message,
    stack: err.stack,
    path: req.url,
    method: req.method
  });

  const statusCode = err.statusCode || 500;
  const errorResponse = {
    error: err.name || 'Internal Server Error',
    message: err.message || 'Something went wrong!',
    timestamp: new Date().toISOString(),
    path: req.url,
    method: req.method,
    ...(process.env.NODE_ENV === 'development' && {
      stack: err.stack,
      details: err
    })
  };

  // Handle specific error types
  if (err.name === 'ValidationError') {
    errorResponse.validationErrors = err.errors;
  } else if (err.name === 'MongoError') {
    errorResponse.databaseError = true;
  } else if (err.name === 'JsonWebTokenError') {
    errorResponse.authError = true;
  }

  res.status(statusCode).json(errorResponse);
});

// Server startup with proper error handling
const startServer = async () => {
  try {
    await connectWithRetry();
    await addMockData('sahanavb23@gmail.com');

    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, () => {
      logger.info('\n🚀 Server Status:');
      logger.info('----------------');
      logger.info(`📡 Server running on port ${PORT}`);
      logger.info(`🌐 API endpoints available at http://localhost:${PORT}/api`);
      logger.info(`📚 Documentation available at http://localhost:${PORT}/api-docs`);
      logger.info(`🔗 Client URL: ${process.env.CLIENT_URL || 'http://localhost:3000'}`);
      logger.info(`💾 Database: Connected`);
      logger.info(`⚙️ Environment: ${process.env.NODE_ENV}`);
      logger.info('----------------\n');
    });

    // Graceful shutdown
    const gracefulShutdown = async () => {
      logger.info('\n⚠️ Initiating graceful shutdown...');
      try {
        await mongoose.connection.close();
        logger.info('✅ MongoDB connection closed');
        process.exit(0);
      } catch (err) {
        logger.error('Error during shutdown:', err);
        process.exit(1);
      }
    };

    // Handle shutdown signals
    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);
    process.on('uncaughtException', (err) => {
      logger.error('Uncaught Exception:', err);
      gracefulShutdown();
    });

    // Handle port conflicts
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        const newPort = PORT + 1;
        logger.info(`Port ${PORT} is already in use. Trying port ${newPort}`);
        const newServer = app.listen(newPort, () => {
          logger.info(`Server running on port ${newPort}`);
        });
      } else {
        logger.error('Server error:', err);
      }
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
validateEnv();
startServer();

// Export app for testing
module.exports = app;

// Function to add mock data for a user
const addMockData = async (email) => {
  try {
    const User = mongoose.model('User');
    const Transaction = mongoose.model('Transaction');
    
    // Find or create user
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        username: 'Sahana',
        email: email,
        password: '12345'
      });
      logger.info('User created successfully');
    }

    // Mock data for 3 months
    const mockTransactions = [
      // January 2024
      {
        userId: user._id,
        type: 'income',
        category: 'Salary',
        amount: 50000,
        description: 'Monthly Salary',
        date: '2024-01-01',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Housing',
        amount: 15000,
        description: 'Rent',
        date: '2024-01-01',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Utilities',
        amount: 5000,
        description: 'Electricity, Water, Internet',
        date: '2024-01-05',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Groceries',
        amount: 8000,
        description: 'Monthly Groceries',
        date: '2024-01-10',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Transportation',
        amount: 3000,
        description: 'Fuel and Public Transport',
        date: '2024-01-15',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Entertainment',
        amount: 2000,
        description: 'Movie Night',
        date: '2024-01-20',
        recurring: false
      },

      // February 2024
      {
        userId: user._id,
        type: 'income',
        category: 'Salary',
        amount: 50000,
        description: 'Monthly Salary',
        date: '2024-02-01',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Housing',
        amount: 15000,
        description: 'Rent',
        date: '2024-02-01',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Utilities',
        amount: 5500,
        description: 'Electricity, Water, Internet',
        date: '2024-02-05',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Groceries',
        amount: 8500,
        description: 'Monthly Groceries',
        date: '2024-02-10',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Healthcare',
        amount: 2000,
        description: 'Doctor Visit',
        date: '2024-02-15',
        recurring: false
      },

      // March 2024
      {
        userId: user._id,
        type: 'income',
        category: 'Salary',
        amount: 50000,
        description: 'Monthly Salary',
        date: '2024-03-01',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Housing',
        amount: 15000,
        description: 'Rent',
        date: '2024-03-01',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Utilities',
        amount: 5200,
        description: 'Electricity, Water, Internet',
        date: '2024-03-05',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Groceries',
        amount: 8200,
        description: 'Monthly Groceries',
        date: '2024-03-10',
        recurring: true
      },
      {
        userId: user._id,
        type: 'expense',
        category: 'Shopping',
        amount: 5000,
        description: 'New Laptop',
        date: '2024-03-20',
        recurring: false
      }
    ];

    // Insert transactions
    await Transaction.insertMany(mockTransactions);
    logger.info('Mock data added successfully');
  } catch (error) {
    logger.error('Error adding mock data:', error);
  }
};

// Update User schema to allow shorter passwords
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 4 } // Changed from 6 to 4
}); 