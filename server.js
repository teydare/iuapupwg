// ============================================
// STUDENTHUB - COMPLETE PRODUCTION BACKEND
// With Railway support, all marketplace routes, trust proxy
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
// RAILWAY FIX: TRUST PROXY (CRITICAL!)
// ============================================
app.set('trust proxy', 1);

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
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
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
    const allowedTypes = /pdf|doc|docx|epub|mobi|txt|jpg|jpeg|png|gif|webp/;
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
    console.error('❌ Database connection error:', err);
  } else {
    console.log('✅ Database connected:', res.rows[0].now);
  }
});

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
// BASIC ROUTES
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'StudentHub API running', timestamp: new Date() });
});

// ============================================
// AUTH ROUTES
// ============================================

app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName, studentId, institution, isCourseRep } = req.body;
  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, full_name, student_id, institution, is_course_rep) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, full_name, student_id, institution, phone, bio, is_course_rep',
      [email, passwordHash, fullName, studentId, institution, isCourseRep || false]
    );
    const user = result.rows[0];
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    res.json({ success: true, token, user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      studentId: user.student_id,
      institution: user.institution,
      phone: user.phone,
      bio: user.bio,
      isCourseRep: user.is_course_rep
    }});
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
    const user = result.rows[0];
    res.json({ success: true, user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      studentId: user.student_id,
      institution: user.institution,
      phone: user.phone,
      bio: user.bio,
      profileImageUrl: user.profile_image_url,
      isCourseRep: user.is_course_rep
    }});
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

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
    const user = result.rows[0];
    res.json({ success: true, user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      studentId: user.student_id,
      institution: user.institution,
      phone: user.phone,
      bio: user.bio,
      isCourseRep: user.is_course_rep
    }});
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// MARKETPLACE GOODS - COMPLETE ROUTES
// ============================================

// GET all items
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

// GET single item with details
app.get('/api/marketplace/goods/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE marketplace_goods SET views = views + 1 WHERE id = $1', [id]);

    const itemResult = await pool.query(
      `SELECT mg.*, u.full_name as seller_name, u.phone as seller_phone, u.email as seller_email
      FROM marketplace_goods mg 
      JOIN users u ON mg.seller_id = u.id 
      WHERE mg.id = $1`,
      [id]
    );

    if (itemResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }

    const favoriteResult = await pool.query(
      'SELECT id FROM favorites WHERE user_id = $1 AND item_id = $2',
      [req.user.userId, id]
    );

    const reviewsResult = await pool.query(
      `SELECT r.*, u.full_name as reviewer_name
      FROM reviews r
      JOIN users u ON r.reviewer_id = u.id
      WHERE r.marketplace_item_id = $1
      ORDER BY r.created_at DESC`,
      [id]
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

// CREATE item with images
app.post('/api/marketplace/goods', authMiddleware, upload.array('images', 5), async (req, res) => {
  const { title, description, price, category, condition, location } = req.body;
  try {
    const imageUrls = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
    
    const result = await pool.query(
      'INSERT INTO marketplace_goods (seller_id, title, description, price, category, condition, location, images) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [req.user.userId, title, description, price, category, condition, location, imageUrls]
    );
    res.json({ success: true, item: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// TOGGLE favorite
app.post('/api/marketplace/goods/:id/favorite', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const existing = await pool.query(
      'SELECT id FROM favorites WHERE user_id = $1 AND item_id = $2',
      [req.user.userId, id]
    );

    if (existing.rows.length > 0) {
      await pool.query('DELETE FROM favorites WHERE user_id = $1 AND item_id = $2', [req.user.userId, id]);
      res.json({ success: true, favorited: false });
    } else {
      await pool.query('INSERT INTO favorites (user_id, item_id) VALUES ($1, $2)', [req.user.userId, id]);
      res.json({ success: true, favorited: true });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET favorites
app.get('/api/marketplace/favorites', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT mg.*, u.full_name as seller_name, u.phone as seller_phone, f.created_at as favorited_at
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

// MAKE offer
app.post('/api/marketplace/goods/:id/offer', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { offerAmount, message } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO offers (item_id, buyer_id, offer_amount, message, status) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [id, req.user.userId, offerAmount, message, 'pending']
    );
    res.json({ success: true, offer: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// CREATE review
app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { reviewedUserId, marketplaceItemId, rating, comment } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO reviews (reviewer_id, reviewed_user_id, marketplace_item_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, reviewedUserId, marketplaceItemId, rating, comment]
    );
    res.json({ success: true, review: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// CLASS SPACES ROUTES
// ============================================

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

app.post('/api/class-spaces', authMiddleware, async (req, res) => {
  const { courseCode, courseName, description, institution, semester, academicYear } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO class_spaces (course_rep_id, course_code, course_name, description, institution, semester, academic_year) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.userId, courseCode, courseName, description, institution, semester, academicYear]
    );
    res.json({ success: true, classSpace: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/class-spaces/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      'INSERT INTO class_space_members (class_space_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [id, req.user.userId]
    );
    res.json({ success: true, message: 'Joined class space' });
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

// ============================================
// LIBRARY ROUTES
// ============================================

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

// ============================================
// MARKETPLACE SERVICES ROUTES
// ============================================

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

// ============================================
// STUDY GROUPS ROUTES
// ============================================

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

// ============================================
// TIMETABLE ROUTES
// ============================================

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

// ============================================
// HOMEWORK HELP ROUTES
// ============================================

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
  res.status(404).json({ success: false, message: 'Route not found', path: req.path });
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
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📡 CORS: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
});
