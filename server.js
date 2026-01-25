// ============================================
// STUDENT PLATFORM - FIXED BACKEND API
// All Issues Resolved
// ============================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================
// MIDDLEWARE
// ============================================

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// File upload setup
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
// DATABASE
// ============================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('✅ Database connected:', res.rows[0].now);
  }
});

app.locals.db = pool;

// ============================================
// DATABASE SCHEMA
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

-- Class Spaces (Course Groups)
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

-- Class Space Resources
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

-- Marketplace Goods
CREATE TABLE IF NOT EXISTS marketplace_goods (
  id SERIAL PRIMARY KEY,
  seller_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  price DECIMAL(10,2) NOT NULL,
  category VARCHAR(100),
  condition VARCHAR(50),
  images TEXT[],
  location VARCHAR(255),
  status VARCHAR(50) DEFAULT 'available',
  views INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Marketplace Services
CREATE TABLE IF NOT EXISTS marketplace_services (
  id SERIAL PRIMARY KEY,
  provider_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
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
// ROUTES
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'StudentHub API is running' });
});

app.post('/api/init-db', async (req, res) => {
  try {
    await pool.query(createTablesSQL);
    res.json({ success: true, message: 'Database initialized successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// AUTH ROUTES - FIXED
// ============================================
// ============================================
// BACKEND ADDITIONS - Add to server.js
// ============================================

// ADD THESE ROUTES TO YOUR SERVER.JS FILE

// ============================================
// STUDY GROUPS - JOIN FUNCTIONALITY
// ============================================

app.post('/api/study-groups/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Check if group exists
    const groupCheck = await pool.query(
      'SELECT * FROM study_groups WHERE id = $1',
      [id]
    );
    
    if (groupCheck.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Study group not found' });
    }
    
    const group = groupCheck.rows[0];
    
    // Check current member count
    const memberCount = await pool.query(
      'SELECT COUNT(*) as count FROM study_group_members WHERE group_id = $1',
      [id]
    );
    
    if (parseInt(memberCount.rows[0].count) >= group.max_members) {
      return res.status(400).json({ success: false, message: 'Group is full' });
    }
    
    // Check if already a member
    const alreadyMember = await pool.query(
      'SELECT * FROM study_group_members WHERE group_id = $1 AND user_id = $2',
      [id, req.user.userId]
    );
    
    if (alreadyMember.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Already a member of this group' });
    }
    
    // Add user to group
    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id, role) VALUES ($1, $2, $3)',
      [id, req.user.userId, 'member']
    );
    
    res.json({ success: true, message: 'Successfully joined study group' });
  } catch (error) {
    console.error('Error joining study group:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// TIMETABLE - DELETE ENTRY
// ============================================

app.delete('/api/timetable/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      'DELETE FROM timetables WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Timetable entry not found' });
    }
    
    res.json({ success: true, message: 'Timetable entry deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// TIMETABLE - UPDATE ENTRY
// ============================================

app.put('/api/timetable/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { title, dayOfWeek, startTime, endTime, location, courseCode, instructor, notes, color } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE timetables 
       SET title = $1, day_of_week = $2, start_time = $3, end_time = $4, 
           location = $5, course_code = $6, instructor = $7, notes = $8, color = $9
       WHERE id = $10 AND user_id = $11 
       RETURNING *`,
      [title, dayOfWeek, startTime, endTime, location, courseCode, instructor, notes, color, id, req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Timetable entry not found' });
    }
    
    res.json({ success: true, entry: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// HOMEWORK HELP - GET RESPONSES
// ============================================

app.get('/api/homework-help/:id/responses', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT hr.*, u.full_name as responder_name 
       FROM homework_responses hr 
       JOIN users u ON hr.responder_id = u.id 
       WHERE hr.help_request_id = $1 
       ORDER BY hr.created_at ASC`,
      [id]
    );
    
    res.json({ success: true, responses: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// PROFILE - GET USER STATISTICS
// ============================================

app.get('/api/auth/profile/stats', authMiddleware, async (req, res) => {
  try {
    // Count classes joined
    const classesResult = await pool.query(
      'SELECT COUNT(*) as count FROM class_space_members WHERE user_id = $1',
      [req.user.userId]
    );
    
    // Count resources uploaded (class + library)
    const classResourcesResult = await pool.query(
      'SELECT COUNT(*) as count FROM class_resources WHERE uploader_id = $1',
      [req.user.userId]
    );
    
    const libraryResourcesResult = await pool.query(
      'SELECT COUNT(*) as count FROM library_resources WHERE uploader_id = $1',
      [req.user.userId]
    );
    
    // Count study groups
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
// FILE DOWNLOAD - INCREMENT COUNTER
// ============================================

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
// FIXED: Now accepts phone number during registration
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

// FIXED: New route to update profile
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

// ============================================
// CLASS SPACES ROUTES - FIXED
// ============================================

// FIXED: Course reps can now create classes
app.post('/api/class-spaces', authMiddleware, async (req, res) => {
  const { courseCode, courseName, description, institution, semester, academicYear } = req.body;
  
  try {
    // Check if user is a course rep
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
    
    // Automatically add the course rep as a member
    await pool.query(
      'INSERT INTO class_space_members (class_space_id, user_id) VALUES ($1, $2)',
      [result.rows[0].id, req.user.userId]
    );
    
    res.json({ success: true, classSpace: result.rows[0] });
  } catch (error) {
    console.error('Error creating class space:', error);
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

// FIXED: Users can now join a class
app.post('/api/class-spaces/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Check if class exists
    const classExists = await pool.query('SELECT * FROM class_spaces WHERE id = $1', [id]);
    if (classExists.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Class not found' });
    }
    
    // Check if already a member
    const memberCheck = await pool.query(
      'SELECT * FROM class_space_members WHERE class_space_id = $1 AND user_id = $2',
      [id, req.user.userId]
    );
    
    if (memberCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Already a member of this class' });
    }
    
    // Add user as member
    await pool.query(
      'INSERT INTO class_space_members (class_space_id, user_id) VALUES ($1, $2)',
      [id, req.user.userId]
    );
    
    res.json({ success: true, message: 'Successfully joined class space' });
  } catch (error) {
    console.error('Error joining class:', error);
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

// ============================================
// MARKETPLACE ROUTES
// ============================================

app.post('/api/marketplace/goods', authMiddleware, async (req, res) => {
  const { title, description, price, category, condition, location } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO marketplace_goods (seller_id, title, description, price, category, condition, location) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.userId, title, description, price, category, condition, location]
    );
    res.json({ success: true, item: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/marketplace/goods', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT mg.*, u.full_name as seller_name, u.phone as seller_phone 
      FROM marketplace_goods mg 
      JOIN users u ON mg.seller_id = u.id 
      WHERE mg.status = 'available' 
      ORDER BY mg.created_at DESC`
    );
    res.json({ success: true, items: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/marketplace/services', authMiddleware, async (req, res) => {
  const { title, description, price, category, serviceCategory, duration, availability } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO marketplace_services (provider_id, title, description, price, category, service_category, duration, availability) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [req.user.userId, title, description, price, category, serviceCategory || 'general', duration, availability]
    );
    res.json({ success: true, service: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/marketplace/services', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ms.*, u.full_name as provider_name, u.phone as provider_phone 
      FROM marketplace_services ms 
      JOIN users u ON ms.provider_id = u.id 
      ORDER BY ms.created_at DESC`
    );
    res.json({ success: true, services: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// STUDY GROUPS ROUTES
// ============================================

app.post('/api/study-groups', authMiddleware, async (req, res) => {
  const { name, description, subject, maxMembers, isPrivate } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO study_groups (creator_id, name, description, subject, max_members, is_private) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [req.user.userId, name, description, subject, maxMembers, isPrivate]
    );
    
    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id, role) VALUES ($1, $2, $3)',
      [result.rows[0].id, req.user.userId, 'admin']
    );
    
    res.json({ success: true, group: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/study-groups', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sg.*, u.full_name as creator_name,
      (SELECT COUNT(*) FROM study_group_members WHERE group_id = sg.id) as member_count
      FROM study_groups sg 
      JOIN users u ON sg.creator_id = u.id 
      WHERE sg.is_private = false 
      ORDER BY sg.created_at DESC`
    );
    res.json({ success: true, groups: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// TIMETABLE ROUTES
// ============================================

app.post('/api/timetable', authMiddleware, async (req, res) => {
  const { title, dayOfWeek, startTime, endTime, location, courseCode, instructor, notes, color } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO timetables (user_id, title, day_of_week, start_time, end_time, location, course_code, instructor, notes, color) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *',
      [req.user.userId, title, dayOfWeek, startTime, endTime, location, courseCode, instructor, notes, color]
    );
    res.json({ success: true, entry: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/timetable', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM timetables WHERE user_id = $1 ORDER BY day_of_week, start_time',
      [req.user.userId]
    );
    res.json({ success: true, entries: result.rows });
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

app.post('/api/homework-help/:id/respond', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { response } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO homework_responses (help_request_id, responder_id, response) VALUES ($1, $2, $3) RETURNING *',
      [id, req.user.userId, response]
    );
    res.json({ success: true, response: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ success: false, message: err.message || 'Internal server error' });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
