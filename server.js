// ============================================
// STUDENT PLATFORM - COMPLETE BACKEND API
// PART 1: Setup, Middleware, Database Schema
// ============================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { Pool } = require('pg');  // ← ADD THIS if not there

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================
// SUPABASE CLIENT (CORRECT METHOD)
// ============================================

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error('❌ Missing Supabase credentials. Check your .env file.');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

// Test connection
(async () => {
  try {
    const { data, error } = await supabase.from('users').select('count').limit(1);
    if (error && error.code !== 'PGRST116') {
      console.error('❌ Database connection error:', error.message);
    } else {
      console.log('✅ Database connected successfully');
    }
  } catch (err) {
    console.error('❌ Database connection error:', err.message);
  }
})();


// ============================================
// MIDDLEWARE - FIXED FOR DEPLOYMENT
// ============================================

// ✅ CRITICAL FIX: Enable trust proxy for Railway/production
app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ✅ FIXED: Rate limiter with proper config for proxy
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// ============================================
// FILE UPLOAD SETUP
// ============================================

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|doc|docx|epub|mobi|txt|jpg|jpeg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Invalid file type'));
  }
});

app.use('/uploads', express.static(uploadDir));

// ============================================

// ============================================
// DATABASE SCHEMA - INCLUDES STORES
// ============================================

const createTablesSQL = `
-- Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  student_id VARCHAR(100),
  institution VARCHAR(255),
  phone VARCHAR(50),
  bio TEXT,
  profile_image_url TEXT,
  is_course_rep BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Stores table (NEW)
CREATE TABLE IF NOT EXISTS stores (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  store_name VARCHAR(255) NOT NULL,
  description TEXT,
  logo_url TEXT,
  banner_url TEXT,
  category VARCHAR(100),
  location VARCHAR(255),
  phone VARCHAR(50),
  email VARCHAR(255),
  website VARCHAR(255),
  is_verified BOOLEAN DEFAULT false,
  rating DECIMAL(3,2) DEFAULT 0.00,
  total_sales INTEGER DEFAULT 0,
  status VARCHAR(50) DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Store followers (NEW)
CREATE TABLE IF NOT EXISTS store_followers (
  id SERIAL PRIMARY KEY,
  store_id INTEGER REFERENCES stores(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  followed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(store_id, user_id)
);

-- Store reviews (NEW)
CREATE TABLE IF NOT EXISTS store_reviews (
  id SERIAL PRIMARY KEY,
  store_id INTEGER REFERENCES stores(id) ON DELETE CASCADE,
  reviewer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  rating INTEGER CHECK (rating >= 1 AND rating <= 5),
  review_text TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(store_id, reviewer_id)
);

-- Class Spaces
CREATE TABLE IF NOT EXISTS class_spaces (
  id SERIAL PRIMARY KEY,
  course_rep_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  course_code VARCHAR(50) NOT NULL,
  course_name VARCHAR(255) NOT NULL,
  description TEXT,
  institution VARCHAR(255),
  semester VARCHAR(50),
  academic_year VARCHAR(20),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Class Space Members
CREATE TABLE IF NOT EXISTS class_space_members (
  id SERIAL PRIMARY KEY,
  class_space_id INTEGER REFERENCES class_spaces(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(class_space_id, user_id)
);

-- Class Resources
CREATE TABLE IF NOT EXISTS class_resources (
  id SERIAL PRIMARY KEY,
  class_space_id INTEGER REFERENCES class_spaces(id) ON DELETE CASCADE,
  uploader_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  file_url TEXT NOT NULL,
  file_type VARCHAR(50),
  file_size BIGINT,
  resource_type VARCHAR(50),
  downloads INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Library Resources
CREATE TABLE IF NOT EXISTS library_resources (
  id SERIAL PRIMARY KEY,
  uploader_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  subject VARCHAR(100),
  file_url TEXT NOT NULL,
  file_type VARCHAR(50),
  file_size BIGINT,
  downloads INTEGER DEFAULT 0,
  is_public BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Marketplace Goods (UPDATED with store_id)
CREATE TABLE IF NOT EXISTS marketplace_goods (
  id SERIAL PRIMARY KEY,
  seller_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  store_id INTEGER REFERENCES stores(id) ON DELETE SET NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  price DECIMAL(10,2) NOT NULL,
  category VARCHAR(100),
  condition VARCHAR(50),
  images TEXT[],
  location VARCHAR(255),
  stock_quantity INTEGER DEFAULT 1,
  status VARCHAR(50) DEFAULT 'available',
  views INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Marketplace Services (UPDATED with store_id)
CREATE TABLE IF NOT EXISTS marketplace_services (
  id SERIAL PRIMARY KEY,
  provider_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  store_id INTEGER REFERENCES stores(id) ON DELETE SET NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  price DECIMAL(10,2) NOT NULL,
  category VARCHAR(100),
  service_category VARCHAR(50) DEFAULT 'general',
  duration VARCHAR(50),
  availability TEXT,
  views INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Study Groups
CREATE TABLE IF NOT EXISTS study_groups (
  id SERIAL PRIMARY KEY,
  creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  subject VARCHAR(100),
  max_members INTEGER DEFAULT 50,
  is_private BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Study Group Members
CREATE TABLE IF NOT EXISTS study_group_members (
  id SERIAL PRIMARY KEY,
  group_id INTEGER REFERENCES study_groups(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(50) DEFAULT 'member',
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(group_id, user_id)
);

-- Chat Messages
CREATE TABLE IF NOT EXISTS chat_messages (
  id SERIAL PRIMARY KEY,
  sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  group_id INTEGER REFERENCES study_groups(id) ON DELETE CASCADE,
  class_space_id INTEGER REFERENCES class_spaces(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  message_type VARCHAR(50) DEFAULT 'text',
  file_url TEXT,
  is_read BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Personal Timetables
CREATE TABLE IF NOT EXISTS timetables (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  day_of_week INTEGER,
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  location VARCHAR(255),
  course_code VARCHAR(50),
  instructor VARCHAR(255),
  notes TEXT,
  color VARCHAR(7) DEFAULT '#3B82F6',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Class Timetables
CREATE TABLE IF NOT EXISTS class_timetables (
  id SERIAL PRIMARY KEY,
  class_space_id INTEGER REFERENCES class_spaces(id) ON DELETE CASCADE,
  day_of_week INTEGER NOT NULL,
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  location_name VARCHAR(255),
  location_address TEXT,
  location_lat DECIMAL(10, 8),
  location_lng DECIMAL(11, 8),
  room_number VARCHAR(50),
  building VARCHAR(100),
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Assignments
CREATE TABLE IF NOT EXISTS assignments (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  class_space_id INTEGER REFERENCES class_spaces(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  due_date TIMESTAMP NOT NULL,
  course VARCHAR(100),
  status VARCHAR(50) DEFAULT 'pending',
  priority VARCHAR(50) DEFAULT 'medium',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Homework Help
CREATE TABLE IF NOT EXISTS homework_help (
  id SERIAL PRIMARY KEY,
  student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  question TEXT NOT NULL,
  subject VARCHAR(100),
  class_space_id INTEGER REFERENCES class_spaces(id),
  attachment_url TEXT,
  status VARCHAR(50) DEFAULT 'open',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Homework Responses
CREATE TABLE IF NOT EXISTS homework_responses (
  id SERIAL PRIMARY KEY,
  help_request_id INTEGER REFERENCES homework_help(id) ON DELETE CASCADE,
  responder_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  response TEXT NOT NULL,
  attachment_url TEXT,
  is_ai_response BOOLEAN DEFAULT false,
  helpful_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_stores_owner ON stores(owner_id);
CREATE INDEX IF NOT EXISTS idx_stores_status ON stores(status);
CREATE INDEX IF NOT EXISTS idx_marketplace_goods_store ON marketplace_goods(store_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_services_store ON marketplace_services(store_id);
CREATE INDEX IF NOT EXISTS idx_class_spaces_rep ON class_spaces(course_rep_id);
CREATE INDEX IF NOT EXISTS idx_class_resources_space ON class_resources(class_space_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_goods_seller ON marketplace_goods(seller_id);
CREATE INDEX IF NOT EXISTS idx_chat_sender ON chat_messages(sender_id);
`;

// ============================================
// AUTH MIDDLEWARE
// ============================================

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// ============================================
// HEALTH & INIT ROUTES
// ============================================

app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'StudentHub API is running',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'StudentHub API is healthy',
    database: pool.totalCount > 0 ? 'connected' : 'disconnected'
  });
});

app.post('/api/init-db', async (req, res) => {
  try {
    await pool.query(createTablesSQL);
    res.json({ success: true, message: 'Database initialized successfully' });
  } catch (error) {
    console.error('Database init error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// EXPORT for use in Part 2

// ============================================
// STUDENT PLATFORM - COMPLETE BACKEND API
// PART 2: Main Routes (Auth, Classes, Library, Marketplace)
// ============================================
// NOTE: This is a continuation. Copy from Part 1 first!

// ============================================
// AUTH ROUTES
// ============================================

app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName, studentId, institution, phone, isCourseRep } = req.body;
  
  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, full_name, student_id, institution, phone, is_course_rep) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, full_name, student_id, institution, phone, is_course_rep',
      [email, passwordHash, fullName, studentId, institution, phone || null, isCourseRep || false]
    );
    
    const user = result.rows[0];
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({ 
      success: true, 
      token, 
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        studentId: user.student_id,
        institution: user.institution,
        phone: user.phone,
        isCourseRep: user.is_course_rep
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        studentId: user.student_id,
        institution: user.institution,
        phone: user.phone,
        bio: user.bio,
        isCourseRep: user.is_course_rep
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, full_name, student_id, institution, phone, bio, profile_image_url, is_course_rep FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  const { fullName, studentId, institution, phone, bio } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE users 
       SET full_name = $1, student_id = $2, institution = $3, phone = $4, bio = $5, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $6 
       RETURNING id, email, full_name, student_id, institution, phone, bio, is_course_rep`,
      [fullName, studentId, institution, phone, bio, req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({ success: true, user: result.rows[0], message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/auth/profile/stats', authMiddleware, async (req, res) => {
  try {
    const classesResult = await pool.query(
      'SELECT COUNT(*) as count FROM class_space_members WHERE user_id = $1',
      [req.user.userId]
    );
    
    const classResourcesResult = await pool.query(
      'SELECT COUNT(*) as count FROM class_resources WHERE uploader_id = $1',
      [req.user.userId]
    );
    
    const libraryResourcesResult = await pool.query(
      'SELECT COUNT(*) as count FROM library_resources WHERE uploader_id = $1',
      [req.user.userId]
    );
    
    const studyGroupsResult = await pool.query(
      'SELECT COUNT(*) as count FROM study_group_members WHERE user_id = $1',
      [req.user.userId]
    );
    
    const stats = {
      classesJoined: parseInt(classesResult.rows[0].count),
      resourcesUploaded: parseInt(classResourcesResult.rows[0].count) + parseInt(libraryResourcesResult.rows[0].count),
      studyGroups: parseInt(studyGroupsResult.rows[0].count)
    };
    
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// CLASS SPACES ROUTES
// ============================================

app.post('/api/class-spaces', authMiddleware, async (req, res) => {
  const { courseCode, courseName, description, institution, semester, academicYear } = req.body;
  
  try {
    const userCheck = await pool.query('SELECT is_course_rep FROM users WHERE id = $1', [req.user.userId]);
    
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (!userCheck.rows[0].is_course_rep) {
      return res.status(403).json({ success: false, message: 'Only course reps can create class spaces' });
    }
    
    const result = await pool.query(
      'INSERT INTO class_spaces (course_rep_id, course_code, course_name, description, institution, semester, academic_year) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.userId, courseCode, courseName, description, institution, semester, academicYear]
    );
    
    await pool.query(
      'INSERT INTO class_space_members (class_space_id, user_id) VALUES ($1, $2)',
      [result.rows[0].id, req.user.userId]
    );
    
    res.json({ success: true, classSpace: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/class-spaces', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT cs.*, u.full_name as rep_name, 
      (SELECT COUNT(*) FROM class_space_members WHERE class_space_id = cs.id) as member_count
      FROM class_spaces cs 
      JOIN users u ON cs.course_rep_id = u.id 
      ORDER BY cs.created_at DESC`
    );
    res.json({ success: true, classSpaces: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/class-spaces/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    const classExists = await pool.query('SELECT * FROM class_spaces WHERE id = $1', [id]);
    if (classExists.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Class not found' });
    }
    
    const memberCheck = await pool.query(
      'SELECT * FROM class_space_members WHERE class_space_id = $1 AND user_id = $2',
      [id, req.user.userId]
    );
    
    if (memberCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Already a member of this class' });
    }
    
    await pool.query(
      'INSERT INTO class_space_members (class_space_id, user_id) VALUES ($1, $2)',
      [id, req.user.userId]
    );
    
    res.json({ success: true, message: 'Successfully joined class space' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/class-spaces/:id/resources', authMiddleware, upload.single('file'), async (req, res) => {
  const { id } = req.params;
  const { title, description, resourceType } = req.body;
  
  try {
    const fileUrl = `/uploads/${req.file.filename}`;
    const result = await pool.query(
      'INSERT INTO class_resources (class_space_id, uploader_id, title, description, file_url, file_type, file_size, resource_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [id, req.user.userId, title, description, fileUrl, req.file.mimetype, req.file.size, resourceType]
    );
    res.json({ success: true, resource: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/class-spaces/:id/resources', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT cr.*, u.full_name as uploader_name 
      FROM class_resources cr 
      JOIN users u ON cr.uploader_id = u.id 
      WHERE cr.class_space_id = $1 
      ORDER BY cr.created_at DESC`,
      [id]
    );
    res.json({ success: true, resources: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/class-spaces/:classId/resources/:resourceId/download', authMiddleware, async (req, res) => {
  const { resourceId } = req.params;
  
  try {
    await pool.query(
      'UPDATE class_resources SET downloads = downloads + 1 WHERE id = $1',
      [resourceId]
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// CLASS TIMETABLE ROUTES
// ============================================

app.post('/api/class-spaces/:id/timetable', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { dayOfWeek, startTime, endTime, locationName, locationAddress, locationLat, locationLng, roomNumber, building, notes } = req.body;
  
  try {
    const classCheck = await pool.query('SELECT course_rep_id FROM class_spaces WHERE id = $1', [id]);
    if (classCheck.rows.length === 0 || classCheck.rows[0].course_rep_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the course rep can set the class timetable' });
    }

    const result = await pool.query(
      'INSERT INTO class_timetables (class_space_id, day_of_week, start_time, end_time, location_name, location_address, location_lat, location_lng, room_number, building, notes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *',
      [id, dayOfWeek, startTime, endTime, locationName, locationAddress, locationLat, locationLng, roomNumber, building, notes]
    );
    res.json({ success: true, entry: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/class-spaces/:id/timetable', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'SELECT * FROM class_timetables WHERE class_space_id = $1 ORDER BY day_of_week, start_time',
      [id]
    );
    res.json({ success: true, entries: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/class-spaces/:classId/timetable/:entryId', authMiddleware, async (req, res) => {
  const { classId, entryId } = req.params;
  try {
    const classCheck = await pool.query('SELECT course_rep_id FROM class_spaces WHERE id = $1', [classId]);
    if (classCheck.rows.length === 0 || classCheck.rows[0].course_rep_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the course rep can delete timetable entries' });
    }

    await pool.query('DELETE FROM class_timetables WHERE id = $1 AND class_space_id = $2', [entryId, classId]);
    res.json({ success: true, message: 'Timetable entry deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// LIBRARY ROUTES
// ============================================

app.post('/api/library', authMiddleware, upload.single('file'), async (req, res) => {
  const { title, description, subject } = req.body;
  
  try {
    const fileUrl = `/uploads/${req.file.filename}`;
    const result = await pool.query(
      'INSERT INTO library_resources (uploader_id, title, description, subject, file_url, file_type, file_size) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.userId, title, description, subject, fileUrl, req.file.mimetype, req.file.size]
    );
    res.json({ success: true, resource: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/library', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lr.*, u.full_name as uploader_name 
      FROM library_resources lr 
      JOIN users u ON lr.uploader_id = u.id 
      WHERE lr.is_public = true 
      ORDER BY lr.created_at DESC`
    );
    res.json({ success: true, resources: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/library/:resourceId/download', authMiddleware, async (req, res) => {
  const { resourceId } = req.params;
  
  try {
    await pool.query(
      'UPDATE library_resources SET downloads = downloads + 1 WHERE id = $1',
      [resourceId]
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// MARKETPLACE ROUTES
// ============================================
// CREATE MARKETPLACE ITEM WITH IMAGES
// Image upload configuration
const imageUpload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB per image
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only image files are allowed'));
  }
});

             
app.post('/api/marketplace/goods', authMiddleware, upload.array('images', 5), async (req, res) => {
  const { title, description, price, category, condition, location } = req.body;
  
  try {
    // Get image URLs
    const imageUrls = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
    
    // Insert into Supabase
    const { data: item, error } = await supabase
      .from('marketplace_goods')
      .insert([{
        seller_id: req.user.userId,
        title,
        description,
        price: parseFloat(price),
        category,
        condition,
        location,
        image_urls: imageUrls,
        status: 'available',
        views: 0
      }])
      .select()
      .single();

    if (error) {
      console.error('Insert error:', error);
      return res.status(500).json({ 
        success: false, 
        error: error.message 
      });
    }

    res.json({ 
      success: true, 
      item 
    });
  } catch (error) {
    console.error('Marketplace create error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// GET MARKETPLACE GOODS
app.get('/api/marketplace/goods', authMiddleware, async (req, res) => {
  try {
    const { data: items, error } = await supabase
      .from('marketplace_goods')
      .select(`
        *,
        users!seller_id (
          full_name,
          phone
        )
      `)
      .eq('status', 'available')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Marketplace query error:', error);
      return res.status(500).json({ 
        success: false, 
        error: error.message 
      });
    }

    // Format the response
    const formattedItems = (items || []).map(item => ({
      ...item,
      seller_name: item.users?.full_name || 'Unknown',
      seller_phone: item.users?.phone || null
    }));

    res.json({ 
      success: true, 
      items: formattedItems 
    });
  } catch (error) {
    console.error('Marketplace error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});
app.post('/api/marketplace/services', authMiddleware, async (req, res) => {
  const { title, description, price, category, serviceCategory, duration, availability, storeId } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO marketplace_services (provider_id, store_id, title, description, price, category, service_category, duration, availability) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
      [req.user.userId, storeId || null, title, description, price, category, serviceCategory || 'general', duration, availability]
    );
    res.json({ success: true, service: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/marketplace/services', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ms.*, u.full_name as provider_name, u.phone as provider_phone, s.store_name
      FROM marketplace_services ms 
      JOIN users u ON ms.provider_id = u.id 
      LEFT JOIN stores s ON ms.store_id = s.id
      ORDER BY ms.created_at DESC`
    );
    res.json({ success: true, services: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// ENHANCED MARKETPLACE ROUTES
// Add these to your server.js after existing marketplace routes
// ============================================

// Image upload configuration for marketplace
const marketplaceUpload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB per image
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only image files are allowed'));
  }
});

// CREATE MARKETPLACE ITEM WITH IMAGES
app.post('/api/marketplace/goods', authMiddleware, marketplaceUpload.array('images', 5), async (req, res) => {
  const { title, description, price, category, condition, location } = req.body;
  try {
    const imageUrls = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
    
    const result = await pool.query(
      'INSERT INTO marketplace_goods (seller_id, title, description, price, category, condition, location, image_urls) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [req.user.userId, title, description, price, category, condition, location, imageUrls]
    );
    res.json({ success: true, item: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET SINGLE MARKETPLACE ITEM WITH DETAILS
app.get('/api/marketplace/goods/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    // Increment view count
    await pool.query(
      'UPDATE marketplace_goods SET views = views + 1 WHERE id = $1',
      [id]
    );

    // Get item with seller info
    const itemResult = await pool.query(
      `SELECT mg.*, u.full_name as seller_name, u.phone as seller_phone, u.email as seller_email,
      (SELECT AVG(rating) FROM reviews WHERE reviewed_user_id = mg.seller_id) as seller_rating,
      (SELECT COUNT(*) FROM reviews WHERE reviewed_user_id = mg.seller_id) as seller_review_count
      FROM marketplace_goods mg 
      JOIN users u ON mg.seller_id = u.id 
      WHERE mg.id = $1`,
      [id]
    );

    if (itemResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }

    // Get reviews for this item
    const reviewsResult = await pool.query(
      `SELECT r.*, u.full_name as reviewer_name
      FROM reviews r
      JOIN users u ON r.reviewer_id = u.id
      WHERE r.marketplace_item_id = $1
      ORDER BY r.created_at DESC`,
      [id]
    );

    // Check if user has favorited
    const favoriteResult = await pool.query(
      'SELECT id FROM favorites WHERE user_id = $1 AND item_id = $2',
      [req.user.userId, id]
    );

    res.json({ 
      success: true, 
      item: itemResult.rows[0],
      reviews: reviewsResult.rows,
      isFavorited: favoriteResult.rows.length > 0
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// UPDATE MARKETPLACE ITEM
app.put('/api/marketplace/goods/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { title, description, price, category, condition, location, status } = req.body;
  
  try {
    // Verify ownership
    const checkResult = await pool.query(
      'SELECT seller_id FROM marketplace_goods WHERE id = $1',
      [id]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }
    
    if (checkResult.rows[0].seller_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the seller can update this item' });
    }

    const result = await pool.query(
      `UPDATE marketplace_goods 
      SET title = $1, description = $2, price = $3, category = $4, condition = $5, location = $6, status = $7
      WHERE id = $8
      RETURNING *`,
      [title, description, price, category, condition, location, status, id]
    );
    
    res.json({ success: true, item: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// FAVORITE/UNFAVORITE ITEM
app.post('/api/marketplace/goods/:id/favorite', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    // Check if already favorited
    const existing = await pool.query(
      'SELECT id FROM favorites WHERE user_id = $1 AND item_id = $2',
      [req.user.userId, id]
    );

    if (existing.rows.length > 0) {
      // Unfavorite
      await pool.query(
        'DELETE FROM favorites WHERE user_id = $1 AND item_id = $2',
        [req.user.userId, id]
      );
      res.json({ success: true, favorited: false });
    } else {
      // Favorite
      await pool.query(
        'INSERT INTO favorites (user_id, item_id) VALUES ($1, $2)',
        [req.user.userId, id]
      );
      res.json({ success: true, favorited: true });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET USER'S FAVORITES
app.get('/api/marketplace/favorites', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT mg.*, u.full_name as seller_name, f.created_at as favorited_at
      FROM favorites f
      JOIN marketplace_goods mg ON f.item_id = mg.id
      JOIN users u ON mg.seller_id = u.id
      WHERE f.user_id = $1
      ORDER BY f.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, favorites: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// MAKE OFFER ON ITEM
app.post('/api/marketplace/goods/:id/offer', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { offerAmount, message } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO offers (item_id, buyer_id, offer_amount, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [id, req.user.userId, offerAmount, message]
    );
    res.json({ success: true, offer: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET OFFERS FOR ITEM (seller only)
app.get('/api/marketplace/goods/:id/offers', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    // Verify seller
    const itemResult = await pool.query(
      'SELECT seller_id FROM marketplace_goods WHERE id = $1',
      [id]
    );
    
    if (itemResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }
    
    if (itemResult.rows[0].seller_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the seller can view offers' });
    }

    const offersResult = await pool.query(
      `SELECT o.*, u.full_name as buyer_name, u.phone as buyer_phone
      FROM offers o
      JOIN users u ON o.buyer_id = u.id
      WHERE o.item_id = $1
      ORDER BY o.created_at DESC`,
      [id]
    );
    
    res.json({ success: true, offers: offersResult.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// RESPOND TO OFFER
app.patch('/api/marketplace/offers/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // accepted or rejected
  
  try {
    // Verify seller ownership
    const offerResult = await pool.query(
      `SELECT o.*, mg.seller_id
      FROM offers o
      JOIN marketplace_goods mg ON o.item_id = mg.id
      WHERE o.id = $1`,
      [id]
    );
    
    if (offerResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Offer not found' });
    }
    
    if (offerResult.rows[0].seller_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the seller can respond to offers' });
    }

    const result = await pool.query(
      'UPDATE offers SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    res.json({ success: true, offer: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ADD REVIEW
app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { reviewedUserId, marketplaceItemId, marketplaceServiceId, rating, comment } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO reviews (reviewer_id, reviewed_user_id, marketplace_item_id, marketplace_service_id, rating, comment) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [req.user.userId, reviewedUserId, marketplaceItemId, marketplaceServiceId, rating, comment]
    );
    res.json({ success: true, review: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET USER REVIEWS
app.get('/api/reviews/user/:userId', authMiddleware, async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      `SELECT r.*, u.full_name as reviewer_name
      FROM reviews r
      JOIN users u ON r.reviewer_id = u.id
      WHERE r.reviewed_user_id = $1
      ORDER BY r.created_at DESC`,
      [userId]
    );
    res.json({ success: true, reviews: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// CHAT/MESSAGING ROUTES
// ============================================

// GET ALL CONVERSATIONS
app.get('/api/chat/conversations', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT ON (other_user_id)
        CASE 
          WHEN sender_id = $1 THEN receiver_id 
          ELSE sender_id 
        END as other_user_id,
        u.full_name as other_user_name,
        u.profile_image_url as other_user_image,
        (SELECT message FROM chat_messages cm2 
         WHERE (cm2.sender_id = $1 AND cm2.receiver_id = other_user_id) 
            OR (cm2.sender_id = other_user_id AND cm2.receiver_id = $1)
         ORDER BY cm2.created_at DESC LIMIT 1) as last_message,
        (SELECT created_at FROM chat_messages cm2 
         WHERE (cm2.sender_id = $1 AND cm2.receiver_id = other_user_id) 
            OR (cm2.sender_id = other_user_id AND cm2.receiver_id = $1)
         ORDER BY cm2.created_at DESC LIMIT 1) as last_message_at,
        (SELECT COUNT(*) FROM chat_messages 
         WHERE sender_id = other_user_id AND receiver_id = $1 AND is_read = false) as unread_count
      FROM chat_messages cm
      LEFT JOIN users u ON u.id = CASE 
        WHEN cm.sender_id = $1 THEN cm.receiver_id 
        ELSE cm.sender_id 
      END
      WHERE (cm.sender_id = $1 OR cm.receiver_id = $1)
        AND cm.group_id IS NULL
        AND cm.class_space_id IS NULL
      ORDER BY other_user_id, last_message_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, conversations: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET MESSAGES WITH A SPECIFIC USER
app.get('/api/chat/messages/:userId', authMiddleware, async (req, res) => {
  const { userId } = req.params;
  try {
    // Mark messages as read
    await pool.query(
      'UPDATE chat_messages SET is_read = true WHERE sender_id = $1 AND receiver_id = $2',
      [userId, req.user.userId]
    );

    // Get messages
    const result = await pool.query(
      `SELECT cm.*, u.full_name as sender_name, u.profile_image_url as sender_image
      FROM chat_messages cm
      JOIN users u ON cm.sender_id = u.id
      WHERE ((cm.sender_id = $1 AND cm.receiver_id = $2) 
         OR (cm.sender_id = $2 AND cm.receiver_id = $1))
        AND cm.group_id IS NULL
        AND cm.class_space_id IS NULL
      ORDER BY cm.created_at ASC`,
      [req.user.userId, userId]
    );
    res.json({ success: true, messages: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// SEND MESSAGE
app.post('/api/chat/messages', authMiddleware, async (req, res) => {
  const { receiverId, groupId, classSpaceId, message, messageType, fileUrl } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO chat_messages (sender_id, receiver_id, group_id, class_space_id, message, message_type, file_url) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.userId, receiverId, groupId, classSpaceId, message, messageType || 'text', fileUrl]
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET UNREAD MESSAGE COUNT
app.get('/api/chat/unread-count', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT COUNT(*) FROM chat_messages WHERE receiver_id = $1 AND is_read = false',
      [req.user.userId]
    );
    res.json({ success: true, count: parseInt(result.rows[0].count) });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET GROUP CHAT MESSAGES
app.get('/api/chat/group/:groupId/messages', authMiddleware, async (req, res) => {
  const { groupId } = req.params;
  try {
    // Verify user is member of group
    const memberCheck = await pool.query(
      'SELECT id FROM study_group_members WHERE group_id = $1 AND user_id = $2',
      [groupId, req.user.userId]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ success: false, message: 'Not a member of this group' });
    }

    const result = await pool.query(
      `SELECT cm.*, u.full_name as sender_name, u.profile_image_url as sender_image
      FROM chat_messages cm
      JOIN users u ON cm.sender_id = u.id
      WHERE cm.group_id = $1
      ORDER BY cm.created_at ASC`,
      [groupId]
    );
    res.json({ success: true, messages: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// SEND GROUP MESSAGE
app.post('/api/chat/group/:groupId/messages', authMiddleware, async (req, res) => {
  const { groupId } = req.params;
  const { message, messageType, fileUrl } = req.body;
  
  try {
    // Verify membership
    const memberCheck = await pool.query(
      'SELECT id FROM study_group_members WHERE group_id = $1 AND user_id = $2',
      [groupId, req.user.userId]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ success: false, message: 'Not a member of this group' });
    }

    const result = await pool.query(
      'INSERT INTO chat_messages (sender_id, group_id, message, message_type, file_url) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, groupId, message, messageType || 'text', fileUrl]
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET CLASS CHAT MESSAGES
app.get('/api/chat/class/:classId/messages', authMiddleware, async (req, res) => {
  const { classId } = req.params;
  try {
    // Verify user is member of class
    const memberCheck = await pool.query(
      'SELECT id FROM class_space_members WHERE class_space_id = $1 AND user_id = $2',
      [classId, req.user.userId]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ success: false, message: 'Not a member of this class' });
    }

    const result = await pool.query(
      `SELECT cm.*, u.full_name as sender_name, u.profile_image_url as sender_image
      FROM chat_messages cm
      JOIN users u ON cm.sender_id = u.id
      WHERE cm.class_space_id = $1
      ORDER BY cm.created_at ASC`,
      [classId]
    );
    res.json({ success: true, messages: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// SEND CLASS MESSAGE
app.post('/api/chat/class/:classId/messages', authMiddleware, async (req, res) => {
  const { classId } = req.params;
  const { message, messageType, fileUrl } = req.body;
  
  try {
    // Verify membership
    const memberCheck = await pool.query(
      'SELECT id FROM class_space_members WHERE class_space_id = $1 AND user_id = $2',
      [classId, req.user.userId]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ success: false, message: 'Not a member of this class' });
    }

    const result = await pool.query(
      'INSERT INTO chat_messages (sender_id, class_space_id, message, message_type, file_url) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, classId, message, messageType || 'text', fileUrl]
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE MESSAGE (sender only)
app.delete('/api/chat/messages/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      'DELETE FROM chat_messages WHERE id = $1 AND sender_id = $2',
      [id, req.user.userId]
    );
    res.json({ success: true, message: 'Message deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});
// Continue to Part 3 for remaining routes...
// ============================================
// HOMEWORK HELP ROUTES
// ============================================

app.post('/api/homework-help', authMiddleware, async (req, res) => {
  const { title, question, subject, classSpaceId } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO homework_help (student_id, title, question, subject, class_space_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, title, question, subject, classSpaceId]
    );
    res.json({ success: true, helpRequest: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/homework-help', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT hh.*, u.full_name as student_name,
      (SELECT COUNT(*) FROM homework_responses WHERE help_request_id = hh.id) as response_count
      FROM homework_help hh 
      JOIN users u ON hh.student_id = u.id 
      ORDER BY hh.created_at DESC`
    );
    res.json({ success: true, requests: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/homework-help/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const requestResult = await pool.query(
      `SELECT hh.*, u.full_name as student_name
      FROM homework_help hh 
      JOIN users u ON hh.student_id = u.id 
      WHERE hh.id = $1`,
      [id]
    );
    
    if (requestResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Request not found' });
    }

    const responsesResult = await pool.query(
      `SELECT hr.*, u.full_name as responder_name
      FROM homework_responses hr
      JOIN users u ON hr.responder_id = u.id
      WHERE hr.help_request_id = $1
      ORDER BY hr.created_at ASC`,
      [id]
    );

    res.json({ 
      success: true, 
      request: requestResult.rows[0],
      responses: responsesResult.rows
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/homework-help/:id/respond', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { response } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO homework_responses (help_request_id, responder_id, response) VALUES ($1, $2, $3) RETURNING *',
      [id, req.user.userId, response]
    );
    
    // Update homework_help status to 'answered' if it was 'open'
    await pool.query(
      "UPDATE homework_help SET status = 'answered' WHERE id = $1 AND status = 'open'",
      [id]
    );
    
    res.json({ success: true, response: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.patch('/api/homework-help/:id/status', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  
  try {
    // Verify the user is the creator of the request
    const checkResult = await pool.query(
      'SELECT student_id FROM homework_help WHERE id = $1',
      [id]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Request not found' });
    }
    
    if (checkResult.rows[0].student_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the creator can update status' });
    }
    
    const result = await pool.query(
      'UPDATE homework_help SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    res.json({ success: true, request: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// PROFILE UPDATE ROUTE
// ============================================

app.patch('/api/auth/profile', authMiddleware, async (req, res) => {
  const { fullName, studentId, institution, phone, bio } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE users 
      SET full_name = $1, student_id = $2, institution = $3, phone = $4, bio = $5, updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
      RETURNING id, email, full_name, student_id, institution, phone, bio, is_course_rep`,
      [fullName, studentId, institution, phone, bio, req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// STATISTICS/DASHBOARD ROUTES
// ============================================

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    // Get various stats for the user
    const classesResult = await pool.query(
      'SELECT COUNT(*) FROM class_space_members WHERE user_id = $1',
      [req.user.userId]
    );
    
    const resourcesResult = await pool.query(
      'SELECT COUNT(*) FROM class_resources WHERE uploader_id = $1',
      [req.user.userId]
    );
    
    const libraryResult = await pool.query(
      'SELECT COUNT(*) FROM library_resources WHERE uploader_id = $1',
      [req.user.userId]
    );
    
    const groupsResult = await pool.query(
      'SELECT COUNT(*) FROM study_group_members WHERE user_id = $1',
      [req.user.userId]
    );
    
    res.json({
      success: true,
      stats: {
        classesJoined: parseInt(classesResult.rows[0].count),
        resourcesUploaded: parseInt(resourcesResult.rows[0].count),
        libraryContributions: parseInt(libraryResult.rows[0].count),
        studyGroups: parseInt(groupsResult.rows[0].count)
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// DELETE/CLEANUP ROUTES
// ============================================

app.delete('/api/timetable/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      'DELETE FROM timetables WHERE id = $1 AND user_id = $2',
      [id, req.user.userId]
    );
    res.json({ success: true, message: 'Timetable entry deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/marketplace/goods/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      'DELETE FROM marketplace_goods WHERE id = $1 AND seller_id = $2',
      [id, req.user.userId]
    );
    res.json({ success: true, message: 'Item deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/marketplace/services/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      'DELETE FROM marketplace_services WHERE id = $1 AND provider_id = $2',
      [id, req.user.userId]
    );
    res.json({ success: true, message: 'Service deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// ERROR HANDLING MIDDLEWARE
// ============================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Route not found',
    path: req.path 
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  // Multer file upload errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ 
      success: false, 
      message: 'File too large. Maximum size is 50MB' 
    });
  }
  
  if (err.message === 'Invalid file type') {
    return res.status(400).json({ 
      success: false, 
      message: 'Invalid file type. Allowed: PDF, DOC, DOCX, EPUB, MOBI, images' 
    });
  }
  
  // Database errors
  if (err.code === '23505') { // Unique constraint violation
    return res.status(400).json({ 
      success: false, 
      message: 'This record already exists' 
    });
  }
  
  if (err.code === '23503') { // Foreign key violation
    return res.status(400).json({ 
      success: false, 
      message: 'Referenced record does not exist' 
    });
  }
  
  // Default error response
  res.status(500).json({ 
    success: false, 
    message: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ============================================
// GRACEFUL SHUTDOWN
// ============================================

process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📝 API URL: http://localhost:${PORT}`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: ${pool.options.connectionString ? 'Connected' : 'Not configured'}`);
  console.log(`\n✅ Initialize database at: http://localhost:${PORT}/api/init-db`);
});

