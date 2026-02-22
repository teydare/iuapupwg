// ============================================
// STUDENTHUB - PRODUCTION SERVER
// WITH SUPABASE STORAGE INTEGRATION
// ============================================
// This server uses Supabase Storage buckets for persistent file storage
// Images and documents survive Railway container restarts

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const pdfExtractor = require('pdf-parse');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const PORT = process.env.PORT || 5000;

const { GoogleGenerativeAI } = require('@google/generative-ai');
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
// ============================================
// SUPABASE STORAGE CLIENT
// ============================================

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // Use service role key for server-side operations
);

// Helper to update reputation and percentile rank
async function updateStudentRank(userId) {
  try {
    // 1. Calculate new reputation score
    const scoreResult = await pool.query(
      `SELECT (COUNT(li.id) * 10) + (SELECT COUNT(*) * 50 FROM y_resources WHERE uploader_id = $1) as total_score
       FROM y_interactions li
       JOIN y_resources lr ON li.resource_id = lr.id
       WHERE lr.uploader_id = $1 AND li.interaction_type = 'upvote'`,
      [userId]
    );
    
    const newScore = scoreResult.rows[0].total_score;
    await pool.query('UPDATE users SET reputation_score = $1 WHERE id = $2', [newScore, userId]);

    // 2. Global Recalculation: Where does this student stand?
    await pool.query(`
      WITH ranks AS (
        SELECT id, PERCENT_RANK() OVER (ORDER BY reputation_score DESC) as p_rank FROM users
      )
      UPDATE users SET rank_percentile = (1 - ranks.p_rank) * 100
      FROM ranks WHERE users.id = ranks.id;
    `);
  } catch (err) {
    console.error('Ranking update failed:', err);
  }
}
// Helper function to upload files to Supabase Storage
async function uploadToSupabase(file, bucket, folder = '') {
  try {
    const fileExt = path.extname(file.originalname);
    const fileName = `${folder}${Date.now()}-${Math.round(Math.random() * 1E9)}${fileExt}`;
    
    const { data, error } = await supabase.storage
      .from(bucket)
      .upload(fileName, file.buffer, {
        contentType: file.mimetype,
        cacheControl: '3600',
        upsert: false
      });

    if (error) {
      console.error('Supabase upload error:', error);
      throw error;
    }

    // Get public URL
    const { data: { publicUrl } } = supabase.storage
      .from(bucket)
      .getPublicUrl(fileName);

    return publicUrl;
  } catch (error) {
    console.error('Upload to Supabase failed:', error);
    throw error;
  }
}

// ============================================
// MIDDLEWARE - FIXED FOR RAILWAY DEPLOYMENT
// ============================================

// ✅ CRITICAL FIX: Enable trust proxy for Railway's X-Forwarded-For header
app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ✅ FIXED: Rate limiter with proper proxy config
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// ============================================
// FILE UPLOAD SETUP - MEMORY STORAGE
// ============================================
// Using memory storage since files go directly to Supabase Storage

const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB for images
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only image files are allowed (JPEG, PNG, GIF, WebP)'));
  }
});

const documentUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB for documents
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|doc|docx|epub|mobi|txt/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only document files are allowed (PDF, DOC, DOCX, EPUB, MOBI, TXT)'));
  }
});

const libraryUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB for documents
  fileFilter: (req, file, cb) => {
    // Allow both PDFs (main file) and images (thumbnail)
    if (file.fieldname === 'file') {
      // Main document must be PDF
      const allowedTypes = /pdf|doc|docx|epub|mobi|txt/;
      const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = allowedTypes.test(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      cb(new Error('Only document files are allowed for main file (PDF, DOC, DOCX, EPUB, MOBI, TXT)'));
    } else if (file.fieldname === 'thumbnail') {
      // Thumbnail must be an image
      const allowedTypes = /jpeg|jpg|png|gif|webp/;
      const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = allowedTypes.test(file.mimetype);
      if (extname && mimetype) {
        return cb(null, true);
      }
      cb(new Error('Only image files are allowed for thumbnail (JPEG, PNG, GIF, WebP)'));
    } else {
      cb(new Error('Unexpected field'));
    }
  }
});

// ============================================
// DATABASE CONNECTION
// ============================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('❌ Unexpected database error:', err);
});

pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database connection error:', err.message);
    console.error('📝 Check your DATABASE_URL environment variable');
  } else {
    console.log('✅ Database connected:', res.rows[0].now);
  }
});

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
-- Table for Upvotes
CREATE TABLE IF NOT EXISTS library_interactions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  resource_id INTEGER REFERENCES library_resources(id) ON DELETE CASCADE,
  interaction_type VARCHAR(50) DEFAULT 'upvote',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, resource_id, interaction_type)
);

-- Table for Bookmarks
CREATE TABLE IF NOT EXISTS library_bookmarks (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  resource_id INTEGER REFERENCES library_resources(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, resource_id)
);
-- Upvotes for Library
CREATE TABLE IF NOT EXISTS library_upvotes (
  id SERIAL PRIMARY KEY,
  resource_id INTEGER REFERENCES library_resources(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(resource_id, user_id)
);

-- Library Bounties (Requests)
CREATE TABLE IF NOT EXISTS library_bounties (
  id SERIAL PRIMARY KEY,
  requester_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  course_code VARCHAR(50) NOT NULL,
  description TEXT,
  reward_points INTEGER DEFAULT 0,
  status VARCHAR(20) DEFAULT 'open',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Marketplace Goods (with images array)
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
  stock_quantity INTEGER DEFAULT 1,
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

-- Favorites
CREATE TABLE IF NOT EXISTS favorites (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  item_id INTEGER REFERENCES marketplace_goods(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, item_id)
);

-- Offers
CREATE TABLE IF NOT EXISTS offers (
  id SERIAL PRIMARY KEY,
  item_id INTEGER REFERENCES marketplace_goods(id) ON DELETE CASCADE,
  buyer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  offer_amount DECIMAL(10,2) NOT NULL,
  message TEXT,
  status VARCHAR(50) DEFAULT 'pending',
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

CREATE TABLE IF NOT EXISTS reviews (
  id SERIAL PRIMARY KEY,
  reviewer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  reviewed_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  marketplace_item_id INTEGER REFERENCES marketplace_goods(id) ON DELETE CASCADE,
  marketplace_service_id INTEGER REFERENCES marketplace_services(id) ON DELETE CASCADE,
  rating INTEGER CHECK (rating >= 1 AND rating <= 5),
  comment TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_class_spaces_rep ON class_spaces(course_rep_id);
CREATE INDEX IF NOT EXISTS idx_class_resources_space ON class_resources(class_space_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_goods_seller ON marketplace_goods(seller_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_goods_status ON marketplace_goods(status);
CREATE INDEX IF NOT EXISTS idx_marketplace_services_provider ON marketplace_services(provider_id);
CREATE INDEX IF NOT EXISTS idx_chat_sender ON chat_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id);
CREATE INDEX IF NOT EXISTS idx_offers_item ON offers(item_id);
CREATE INDEX IF NOT EXISTS idx_reviews_item ON reviews(marketplace_item_id);
CREATE INDEX IF NOT EXISTS idx_reviews_user ON reviews(reviewed_user_id);
`;



// ============================================
// AUTH MIDDLEWARE
// ============================================

// ============================================
// 1. FIXED AUTH MIDDLEWARE (Resolves 401 Errors)
// ============================================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    console.error("JWT Verify Error:", error.message);
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};


// ============================================
// HEALTH & INIT ROUTES
// ============================================

app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'StudentHub API is running',
    timestamp: new Date().toISOString(),
    storage: 'Supabase Storage'
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'StudentHub API is healthy',
    database: pool.totalCount > 0 ? 'connected' : 'disconnected',
    storage: 'Supabase Storage'
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

// ============================================
// AUTH ROUTES
// ============================================

//

app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName, studentId, institution, phone, isCourseRep } = req.body;
  
  try {
    // 1. Check if Email exists
    const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    // 2. Check if Student ID exists
    const idCheck = await pool.query('SELECT id FROM users WHERE student_id = $1', [studentId]);
    if (idCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Student ID already registered' });
    }

    // 3. Check if Phone Number exists
    const phoneCheck = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    if (phoneCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Phone number already linked to an account' });
    }
    
    // 4. Create User
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, full_name, student_id, institution, phone, is_course_rep) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, full_name, student_id, institution, phone, is_course_rep',
      [email, passwordHash, fullName, studentId, institution, phone, isCourseRep || false]
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
    console.error("Registration error:", error);
    // Handle database constraint violations gracefully if race conditions occur
    if (error.code === '23505') { // Postgres unique violation code
      if (error.constraint === 'users_email_key') return res.status(400).json({ success: false, message: 'Email already exists' });
      if (error.constraint === 'users_student_id_key') return res.status(400).json({ success: false, message: 'Student ID already exists' });
      if (error.constraint === 'users_phone_key') return res.status(400).json({ success: false, message: 'Phone number already exists' });
    }
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
        isCourseRep: user.is_course_rep,
        profileImageUrl: user.profile_image_url
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
    
    res.json({ success: true, user: result.rows[0], message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});
// Add this under the existing /api/auth/profile routes
app.get('/api/auth/stats', authMiddleware, async (req, res) => {
  try {
   const userId = req.user.userId;

    // 1. Calculate Reputation for EVERY user to determine ranking
    // This query creates a virtual table of all user reputations
    const rankResult = await pool.query(`
      WITH UserReputations AS (
        SELECT 
          u.id,
          (
            (SELECT COUNT(*) FROM library_resources WHERE uploader_id = u.id) * 10 +
            (SELECT COUNT(*) FROM library_interactions li 
             JOIN library_resources lr ON li.resource_id = lr.id 
             WHERE lr.uploader_id = u.id AND li.interaction_type = 'upvote') * 5
          ) as total_rep
        FROM users u
      )
      SELECT 
        total_rep,
        (SELECT COUNT(*) FROM UserReputations) as total_users,
        (SELECT COUNT(*) FROM UserReputations WHERE total_rep > (SELECT total_rep FROM UserReputations WHERE id = $1)) as users_above
      FROM UserReputations 
      WHERE id = $1
    `, [userId]);

    if (rankResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const { total_rep, total_users, users_above } = rankResult.rows[0];

    // 2. Calculate Real Percentile
    // Formula: (Number of people below you / Total people) * 100
    // We want "Top X%", so: (Users Above / Total Users) * 100
    let percentile = Math.round((parseInt(users_above) / parseInt(total_users)) * 100);
    
    // Ensure it doesn't say "Top 0%"
    if (percentile === 0) percentile = 1;

    // 3. Get individual counts for the UI display
    const uploadCount = await pool.query('SELECT COUNT(*) FROM library_resources WHERE uploader_id = $1', [userId]);
    const upvoteCount = await pool.query(`
      SELECT COUNT(*) FROM library_interactions li
      JOIN library_resources lr ON li.resource_id = lr.id
      WHERE lr.uploader_id = $1 AND li.interaction_type = 'upvote'
    `, [userId]);

    const classesCount = await pool.query(
      'SELECT COUNT(*) FROM class_space_members WHERE user_id = $1',
      [userId]
    );

    const resourcesCount = await pool.query(
      'SELECT COUNT(*) FROM class_resources WHERE uploader_id = $1',
      [userId]
    );

    const groupsCount = await pool.query(
      'SELECT COUNT(*) FROM study_group_members WHERE user_id = $1',
      [userId]
    );

    const itemsSold = await pool.query(
      'SELECT COUNT(*) FROM marketplace_goods WHERE seller_id = $1',
      [userId]
    );

    const reviewsReceived = await pool.query(
      'SELECT COUNT(*) FROM reviews WHERE reviewed_user_id = $1',
      [userId]
    );

    const avgRating = await pool.query(
      'SELECT COALESCE(AVG(rating),0)::numeric(10,1) as avg FROM reviews WHERE reviewed_user_id = $1',
      [userId]
    );

    res.json({
      success: true,
      stats: {
        classesJoined: parseInt(classesCount.rows[0].count),
        resourcesUploaded: parseInt(resourcesCount.rows[0].count),
        studyGroups: parseInt(groupsCount.rows[0].count),
        itemsSold: parseInt(itemsSold.rows[0].count),
        reviewsReceived: parseInt(reviewsReceived.rows[0].count),
        avgRating: parseFloat(avgRating.rows[0].avg),
        reputation: parseInt(total_rep),
        uploads: parseInt(uploadCount.rows[0].count),
        upvotes: parseInt(upvoteCount.rows[0].count),
        percentile: percentile
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message });
  }
});


// Upload profile avatar
app.post('/api/auth/avatar', authMiddleware, imageUpload.single('avatar'), async (req, res) => {
  try {
    const publicUrl = await uploadToSupabase(
      req.file,
      'profile-images',
      `user-${req.user.userId}/`
    );

    await pool.query(
      'UPDATE users SET profile_image_url = $1 WHERE id = $2',
      [publicUrl, req.user.userId]
    );

    res.json({
      success: true,
      url: publicUrl
    });

  } catch (error) {
    console.error('Avatar upload error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// MARKETPLACE ROUTES WITH SUPABASE STORAGE
// ============================================

app.post('/api/marketplace/goods', authMiddleware, imageUpload.array('images', 5), async (req, res) => {
  const { title, description, price, category, condition, location } = req.body;
  
  try {
    let imageUrls = [];
    
    // Upload images to Supabase Storage
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const publicUrl = await uploadToSupabase(file, 'marketplace-images', 'goods/');
        imageUrls.push(publicUrl);
      }
    }
    
    const result = await pool.query(
      'INSERT INTO marketplace_goods (seller_id, title, description, price, category, condition, location, images) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [req.user.userId, title, description, price, category, condition, location, imageUrls]
    );
    
    res.json({ success: true, item: result.rows[0] });
  } catch (error) {
    console.error('Error creating marketplace item:', error);
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

app.get('/api/marketplace/goods/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Increment view count
    await pool.query('UPDATE marketplace_goods SET views = views + 1 WHERE id = $1', [id]);
    
    // UPDATED QUERY: Includes subqueries for seller_rating and seller_review_count
    const itemResult = await pool.query(
      `SELECT mg.*, 
              u.full_name as seller_name, 
              u.phone as seller_phone, 
              u.email as seller_email,
              (SELECT AVG(rating)::numeric(10,1) FROM reviews WHERE reviewed_user_id = mg.seller_id) as seller_rating,
              (SELECT COUNT(*) FROM reviews WHERE reviewed_user_id = mg.seller_id) as seller_review_count
      FROM marketplace_goods mg 
      JOIN users u ON mg.seller_id = u.id 
      WHERE mg.id = $1`,
      [id]
    );
    
    if (itemResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }
    
    // Check if favorited
    const favoriteResult = await pool.query(
      'SELECT id FROM favorites WHERE user_id = $1 AND item_id = $2',
      [req.user.userId, id]
    );
    
    // Return item with all seller stats
    res.json({ 
      success: true, 
      item: {
        ...itemResult.rows[0],
        seller_rating: parseFloat(itemResult.rows[0].seller_rating) || 0, // Ensure number format
        seller_review_count: parseInt(itemResult.rows[0].seller_review_count) || 0
      },
      isFavorited: favoriteResult.rows.length > 0
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/marketplace/goods/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { title, description, price, category, condition, location, status } = req.body;
  
  try {
    const checkResult = await pool.query('SELECT seller_id FROM marketplace_goods WHERE id = $1', [id]);
    
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

// Favorites
app.post('/api/marketplace/goods/:id/favorite', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    const existing = await pool.query(
      'SELECT id FROM favorites WHERE user_id = $1 AND item_id = $2',
      [req.user.userId, id]
    );

    if (existing.rows.length > 0) {
      await pool.query(
        'DELETE FROM favorites WHERE user_id = $1 AND item_id = $2',
        [req.user.userId, id]
      );
      res.json({ success: true, favorited: false });
    } else {
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

// Offers
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

app.get('/api/marketplace/goods/:id/offers', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    const itemResult = await pool.query('SELECT seller_id FROM marketplace_goods WHERE id = $1', [id]);
    
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
// ============================================
// UPDATED MARKETPLACE REVIEWS ROUTES
// ============================================

// ============================================
// MARKETPLACE REVIEWS API
// ============================================

//
// ============================================
// MARKETPLACE REVIEWS API
// ============================================

// 1. GET REVIEWS (With User Info)
// 1. GET REVIEWS (With User Info)
app.get('/api/reviews/:itemId', authMiddleware, async (req, res) => {
  const { itemId } = req.params;

  try {
    const result = await pool.query(
      `SELECT 
         r.id,
         r.rating,
         r.comment,
         r.created_at,
         r.reviewer_id,
         u.full_name AS reviewer_name,
         u.profile_image_url AS reviewer_image
       FROM reviews r
       LEFT JOIN users u 
         ON u.id = r.reviewer_id
       WHERE r.marketplace_item_id = $1
       ORDER BY r.created_at DESC`,
      [itemId]
    );

    const stats = await pool.query(
      `SELECT 
         COALESCE(AVG(rating),0)::numeric(10,1) AS average,
         COUNT(*) AS count
       FROM reviews
       WHERE marketplace_item_id = $1`,
      [itemId]
    );

    res.json({
      success: true,
      reviews: result.rows,
      stats: stats.rows[0]
    });

  } catch (error) {
    console.error('Fetch reviews error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 2. SUBMIT REVIEW
// 2. SUBMIT REVIEW
app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { itemId, rating, comment, reviewedUserId } = req.body;

  try {
    const insert = await pool.query(
      `INSERT INTO reviews 
       (marketplace_item_id, reviewer_id, reviewed_user_id, rating, comment) 
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, marketplace_item_id, reviewer_id, rating, comment, created_at`,
      [itemId, req.user.userId, reviewedUserId, rating, comment]
    );

    const review = insert.rows[0];

    // 🔽 Immediately join user info for frontend
    const withUser = await pool.query(
      `SELECT 
         $1::int AS id,
         $2::int AS reviewer_id,
         $3::int AS marketplace_item_id,
         $4::int AS rating,
         $5::text AS comment,
         $6::timestamp AS created_at,
         u.full_name AS reviewer_name,
         u.profile_image_url AS reviewer_image
       FROM users u
       WHERE u.id = $2`,
      [
        review.id,
        review.reviewer_id,
        review.marketplace_item_id,
        review.rating,
        review.comment,
        review.created_at
      ]
    );

    res.json({
      success: true,
      review: withUser.rows[0]
    });

  } catch (error) {
    console.error('Submit review error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Public seller store
// ================================
// PUBLIC STORE PAGE
// ================================
// ==========================================
// ✅ FIX: GET STORE (Robust Handler)
// Handles both User ID lookup and Store Metadata
// ==========================================
app.get('/api/store/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;

  try {
    // Validate ID is a number to prevent SQL injection/crashes
    if (isNaN(id)) {
      return res.status(400).json({ success: false, message: 'Invalid ID format' });
    }

    // 1. Fetch Basic Info (Join Users + Stores)
    // We LEFT JOIN stores on users because every seller is a user, 
    // but not every user has a customized 'store' entry yet.
    const storeQuery = `
      SELECT 
        u.id as user_id,
        u.full_name,
        u.email,
        u.phone as whatsapp_number,
        u.profile_image_url,
        u.bio as user_bio,
        u.created_at,
        u.is_course_rep,
        s.id as store_id,
        s.store_name,
        s.slug,
        s.description as store_description,
        s.banner_url
      FROM users u
      LEFT JOIN stores s ON u.id = s.user_id
      WHERE u.id = $1
    `;
    
    const userResult = await pool.query(storeQuery, [id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Seller not found' });
    }

    const rawData = userResult.rows[0];

    // 2. Calculate Ratings from Reviews Table
    const statsQuery = `
      SELECT 
        COALESCE(AVG(rating), 0)::numeric(10,1) as avg_rating,
        COUNT(id) as total_reviews
      FROM reviews 
      WHERE reviewed_user_id = $1
    `;
    const statsResult = await pool.query(statsQuery, [id]);

    // 3. Construct "Seller/Store" Object for Frontend
    // Priority: Store Name > User Name, Store Desc > User Bio
    const storeObj = {
      id: rawData.user_id, // Frontend uses seller_id as the primary key
      store_id: rawData.store_id,
      full_name: rawData.store_name || rawData.full_name,
      bio: rawData.store_description || rawData.user_bio,
      profile_image_url: rawData.profile_image_url,
      banner_url: rawData.banner_url,
      whatsapp_number: rawData.whatsapp_number,
      created_at: rawData.created_at,
      location: rawData.institution || 'Campus', // Fallback if location not in table
      seller_rating: statsResult.rows[0].avg_rating,
      seller_review_count: statsResult.rows[0].total_reviews,
      is_verified: rawData.is_course_rep // Example logic for verification tag
    };

    // 4. Fetch Active Products
    const itemsQuery = `
      SELECT * FROM marketplace_goods 
      WHERE seller_id = $1 AND status = 'available' 
      ORDER BY created_at DESC
    `;
    const itemsResult = await pool.query(itemsQuery, [id]);

    res.json({
      success: true,
      store: storeObj,
      items: itemsResult.rows
    });

  } catch (error) {
    console.error('Get store error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// ✅ FIX: GET REVIEWS
// Correctly joins users table for reviewer details
// ==========================================
app.get('/api/reviews/user/:userId', authMiddleware, async (req, res) => {
  const { userId } = req.params;

  try {
    if (isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid User ID' });
    }

    // Query 'reviews' table, join 'users' to get the reviewer's name/pic
    const query = `
      SELECT 
        r.id, 
        r.rating, 
        r.comment, 
        r.created_at,
        r.reviewer_id,
        u.full_name,
        u.profile_image_url as avatar
      FROM reviews r
      JOIN users u ON r.reviewer_id = u.id
      WHERE r.reviewed_user_id = $1
      ORDER BY r.created_at DESC
    `;

    const result = await pool.query(query, [userId]);

    // Map to frontend structure if necessary, or send as is
    const formattedReviews = result.rows.map(row => ({
      id: row.id,
      rating: row.rating,
      comment: row.comment,
      created_at: row.created_at,
      user: {
        id: row.reviewer_id,
        full_name: row.full_name,
        avatar: row.avatar
      }
    }));

    res.json({ 
      success: true, 
      reviews: formattedReviews 
    });

  } catch (error) {
    console.error('Get reviews error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});
// Get all stores
app.get('/api/stores', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, u.full_name as owner_name,
       (SELECT COUNT(*) FROM store_followers WHERE store_id = s.id) as followers_count,
       (SELECT COUNT(*) FROM marketplace_goods WHERE store_id = s.id AND status = 'available') as products_count
       FROM stores s
       JOIN users u ON s.owner_id = u.id
       WHERE s.status = 'active'
       ORDER BY s.created_at DESC`
    );

    res.json({ success: true, stores: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a new store
app.post('/api/stores', authMiddleware, async (req, res) => {
  const { storeName, description, category, location, phone, email, website } = req.body;
  
  try {
    // Check if user already has a store
    const existingStore = await pool.query(
      'SELECT id FROM stores WHERE owner_id = $1',
      [req.user.userId]
    );

    if (existingStore.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'You already have a store. Each user can only create one store.' 
      });
    }

    const result = await pool.query(
      `INSERT INTO stores (owner_id, store_name, description, category, location, phone, email, website)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [req.user.userId, storeName, description, category, location, phone, email, website]
    );

    res.json({ success: true, store: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update store
app.put('/api/stores/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { storeName, description, category, location, phone, email, website } = req.body;
  
  try {
    // Verify ownership
    const storeCheck = await pool.query(
      'SELECT owner_id FROM stores WHERE id = $1',
      [id]
    );

    if (storeCheck.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Store not found' });
    }

    if (storeCheck.rows[0].owner_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the store owner can update this store' });
    }

    const result = await pool.query(
      `UPDATE stores
       SET store_name = $1, description = $2, category = $3, location = $4, 
           phone = $5, email = $6, website = $7
       WHERE id = $8
       RETURNING *`,
      [storeName, description, category, location, phone, email, website, id]
    );

    res.json({ success: true, store: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Follow/Unfollow store
app.post('/api/stores/:id/follow', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Check if already following
    const existing = await pool.query(
      'SELECT id FROM store_followers WHERE store_id = $1 AND user_id = $2',
      [id, req.user.userId]
    );

    if (existing.rows.length > 0) {
      // Unfollow
      await pool.query(
        'DELETE FROM store_followers WHERE store_id = $1 AND user_id = $2',
        [id, req.user.userId]
      );
      res.json({ success: true, following: false });
    } else {
      // Follow
      await pool.query(
        'INSERT INTO store_followers (store_id, user_id) VALUES ($1, $2)',
        [id, req.user.userId]
      );
      res.json({ success: true, following: true });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get user's store (if they have one)
app.get('/api/stores/my-store', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*,
       (SELECT COUNT(*) FROM store_followers WHERE store_id = s.id) as followers_count,
       (SELECT COUNT(*) FROM marketplace_goods WHERE store_id = s.id) as products_count
       FROM stores s
       WHERE s.owner_id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.json({ success: true, store: null });
    }

    res.json({ success: true, store: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// REVIEW ROUTES
// ============================================

// Get reviews for a user
app.get('/api/reviews/user/:userId', authMiddleware, async (req, res) => {
  const { userId } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT sr.*, u.full_name as reviewer_name, s.store_name
       FROM store_reviews sr
       JOIN users u ON sr.reviewer_id = u.id
       LEFT JOIN stores s ON sr.store_id = s.id
       WHERE s.owner_id = $1
       ORDER BY sr.created_at DESC`,
      [userId]
    );

    // Calculate average rating
    const avgResult = await pool.query(
      `SELECT AVG(sr.rating) as avg_rating, COUNT(*) as total_reviews
       FROM store_reviews sr
       JOIN stores s ON sr.store_id = s.id
       WHERE s.owner_id = $1`,
      [userId]
    );

    res.json({ 
      success: true, 
      reviews: result.rows,
      averageRating: parseFloat(avgResult.rows[0].avg_rating) || 0,
      totalReviews: parseInt(avgResult.rows[0].total_reviews) || 0
    });
  } catch (error) {
    console.error('Get reviews error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get reviews for a store
app.get('/api/reviews/store/:storeId', authMiddleware, async (req, res) => {
  const { storeId } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT sr.*, u.full_name as reviewer_name, u.profile_image_url as reviewer_image
       FROM store_reviews sr
       JOIN users u ON sr.reviewer_id = u.id
       WHERE sr.store_id = $1
       ORDER BY sr.created_at DESC`,
      [storeId]
    );

    res.json({ success: true, reviews: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a review
app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { storeId, rating, reviewText } = req.body;
  
  try {
    // Check if store exists
    const storeCheck = await pool.query(
      'SELECT id, owner_id FROM stores WHERE id = $1',
      [storeId]
    );

    if (storeCheck.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Store not found' });
    }

    // Prevent reviewing own store
    if (storeCheck.rows[0].owner_id === req.user.userId) {
      return res.status(400).json({ success: false, message: 'You cannot review your own store' });
    }

    // Check if already reviewed
    const existingReview = await pool.query(
      'SELECT id FROM store_reviews WHERE store_id = $1 AND reviewer_id = $2',
      [storeId, req.user.userId]
    );

    if (existingReview.rows.length > 0) {
      // Update existing review
      const result = await pool.query(
        `UPDATE store_reviews 
         SET rating = $1, review_text = $2, created_at = CURRENT_TIMESTAMP
         WHERE store_id = $3 AND reviewer_id = $4
         RETURNING *`,
        [rating, reviewText, storeId, req.user.userId]
      );

      // Update store average rating
      await updateStoreRating(storeId);

      res.json({ success: true, review: result.rows[0], message: 'Review updated' });
    } else {
      // Create new review
      const result = await pool.query(
        `INSERT INTO store_reviews (store_id, reviewer_id, rating, review_text)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [storeId, req.user.userId, rating, reviewText]
      );

      // Update store average rating
      await updateStoreRating(storeId);

      res.json({ success: true, review: result.rows[0], message: 'Review created' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Helper function to update store rating
async function updateStoreRating(storeId) {
  try {
    const avgResult = await pool.query(
      'SELECT AVG(rating) as avg_rating FROM store_reviews WHERE store_id = $1',
      [storeId]
    );

    const avgRating = parseFloat(avgResult.rows[0].avg_rating) || 0;

    await pool.query(
      'UPDATE stores SET rating = $1 WHERE id = $2',
      [avgRating.toFixed(2), storeId]
    );
  } catch (error) {
    console.error('Update store rating error:', error);
  }
}

// Delete a review (reviewer only)
app.delete('/api/reviews/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    const reviewCheck = await pool.query(
      'SELECT reviewer_id, store_id FROM store_reviews WHERE id = $1',
      [id]
    );

    if (reviewCheck.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Review not found' });
    }

    if (reviewCheck.rows[0].reviewer_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the reviewer can delete this review' });
    }

    const storeId = reviewCheck.rows[0].store_id;

    await pool.query('DELETE FROM store_reviews WHERE id = $1', [id]);

    // Update store rating
    await updateStoreRating(storeId);

    res.json({ success: true, message: 'Review deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/store/:sellerId', async (req,res) => {
  const { sellerId } = req.params;

  try {

    await pool.query(
      `UPDATE users SET store_views = store_views + 1 WHERE id=$1`,
      [sellerId]
    );

    const seller = await pool.query(`
      SELECT 
        u.*,
        COUNT(DISTINCT f.id) as follower_count,
        COALESCE(AVG(r.rating),0)::numeric(10,1) as rating,
        COUNT(DISTINCT r.id) as review_count
      FROM users u
      LEFT JOIN seller_followers f ON f.seller_id=u.id
      LEFT JOIN reviews r ON r.reviewed_user_id=u.id
      WHERE u.id=$1
      GROUP BY u.id
    `,[sellerId]);

    const items = await pool.query(`
      SELECT 
        g.*,
        COALESCE(AVG(r.rating),0)::numeric(10,1) as rating,
        COUNT(r.id) as review_count
      FROM marketplace_goods g
      LEFT JOIN reviews r ON r.marketplace_item_id=g.id
      WHERE g.seller_id=$1
      GROUP BY g.id
      ORDER BY g.created_at DESC
    `,[sellerId]);

    res.json({
      success:true,
      store: seller.rows[0],
      items: items.rows
    });

  } catch(err){
    res.status(500).json({success:false,error:err.message});
  }
});

app.post('/api/store/:sellerId/follow', authMiddleware, async (req,res) => {
  await pool.query(`
    INSERT INTO seller_followers (seller_id,follower_id)
    VALUES ($1,$2)
    ON CONFLICT DO NOTHING
  `,[req.params.sellerId, req.user.id]);

  res.json({success:true});
});

app.delete('/api/store/:sellerId/follow', authMiddleware, async (req,res) => {
  await pool.query(`
    DELETE FROM seller_followers
    WHERE seller_id=$1 AND follower_id=$2
  `,[req.params.sellerId, req.user.id]);

  res.json({success:true});
});

app.patch('/api/store/profile', authMiddleware, async (req,res) => {
  const { store_description, store_slug } = req.body;

  await pool.query(`
    UPDATE users
    SET store_description=$1,
        store_slug=$2
    WHERE id=$3
  `,[store_description, store_slug, req.user.id]);

  res.json({success:true});
});


 
app.get('/api/store/:idOrSlug', async (req, res) => {
  const { idOrSlug } = req.params;

  const store = await pool.query(`
    SELECT s.*, u.full_name, u.profile_image_url
    FROM stores s
    JOIN users u ON s.user_id = u.id
    WHERE s.user_id::text = $1 OR s.slug = $1
  `, [idOrSlug]);

  if (!store.rows.length) {
    return res.status(404).json({ success: false });
  }

  const items = await pool.query(`
    SELECT *
    FROM marketplace_goods
    WHERE seller_id = $1
    ORDER BY created_at DESC
  `, [store.rows[0].user_id]);

  res.json({
    success: true,
    store: store.rows[0],
    items: items.rows
  });
});

app.get('/api/store/:id', async (req,res) => {
  const store = await db('stores').where({ id: req.params.id }).first();
  const items = await db('items').where({ store_id: req.params.id });

  res.json({ success: true, store, items });
});
app.post('/api/items/:id/whatsapp', async (req,res)=>{
  await db('item_events').insert({
    item_id: req.params.id,
    event_type: 'whatsapp_click'
  });
  res.json({ success: true });
});

// Marketplace Services
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
// CLASS SPACES ROUTES WITH SUPABASE STORAGE
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
    
    await pool.query(
      'INSERT INTO class_space_members (class_space_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [id, req.user.userId]
    );
    
    res.json({ success: true, message: 'Successfully joined class space' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/class-spaces/:id/resources', authMiddleware, documentUpload.single('file'), async (req, res) => {
  const { id } = req.params;
  const { title, description, resourceType } = req.body;
  
  try {
    // Upload to Supabase Storage
    const fileUrl = await uploadToSupabase(req.file, 'class-resources', `class-${id}/`);
    
    const result = await pool.query(
      'INSERT INTO class_resources (class_space_id, uploader_id, title, description, file_url, file_type, file_size, resource_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [id, req.user.userId, title, description, fileUrl, req.file.mimetype, req.file.size, resourceType]
    );
    
    res.json({ success: true, resource: result.rows[0] });
  } catch (error) {
    console.error('Error uploading class resource:', error);
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

// Class Timetable
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
// Y ROUTES WITH SUPABASE STORAGE
// ============================================

// ============================================
// LIBRARY RESOURCES - FINAL SYNCED VERSION
// ============================================

// 1. GET ALL RESOURCES (Includes Upvote/Bookmark status)
app.get('/api/library', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lr.*, u.full_name as uploader_name,
        (SELECT COUNT(*) FROM library_interactions WHERE resource_id = lr.id AND interaction_type = 'upvote') as upvotes,
        EXISTS(SELECT 1 FROM library_interactions WHERE resource_id = lr.id AND user_id = $1 AND interaction_type = 'upvote') as has_upvoted,
        EXISTS(SELECT 1 FROM library_bookmarks WHERE resource_id = lr.id AND user_id = $1) as is_bookmarked
      FROM library_resources lr 
      JOIN users u ON lr.uploader_id = u.id 
      WHERE lr.is_public = true 
      ORDER BY lr.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, resources: result.rows });
  } catch (error) {
    console.error('Library Fetch Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 2. GET USER BOOKMARKS - FIXES THE 404 ERROR
// Note: This must be ABOVE /api/library/:id routes
app.get('/api/library/bookmarks', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT resource_id FROM library_bookmarks WHERE user_id = $1`,
      [req.user.userId]
    );
    res.json({ success: true, bookmarks: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 3. UPLOAD RESOURCE - UPDATED TO INCLUDE CATEGORY
// UPDATED: Upload Resource (Supports PDF + Optional Thumbnail)
const uploadFields = [
  { name: 'file', maxCount: 1 }, 
  { name: 'thumbnail', maxCount: 1 }
];

// Replace the existing POST /api/library route with this:
app.post('/api/library', authMiddleware, libraryUpload.fields([
  { name: 'file', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  const { title, description, subject, category } = req.body;
  
  try {
    if (!req.files || !req.files.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }

    const mainFile = req.files.file[0];
    const thumbnailFile = req.files.thumbnail ? req.files.thumbnail[0] : null;

    // Upload main file to Supabase Storage (Bucket: library-resources)
    const fileUrl = await uploadToSupabase(mainFile, 'library-resources', 'documents/');
    
    // Upload thumbnail if provided
    let thumbnailUrl = null;
    if (thumbnailFile) {
      thumbnailUrl = await uploadToSupabase(thumbnailFile, 'library-resources', 'thumbnails/');
    }
    
    const result = await pool.query(
      `INSERT INTO library_resources 
       (uploader_id, title, description, subject, category, file_url, thumbnail_url, file_type, file_size) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [
        req.user.userId, 
        title, 
        description, 
        subject, 
        category || 'Lecture Notes', 
        fileUrl, 
        thumbnailUrl,
        mainFile.mimetype, 
        mainFile.size
      ]
    );
    
    // Update user reputation
    await updateStudentRank(req.user.userId);
    
    res.json({ success: true, resource: result.rows[0] });
  } catch (error) {
    console.error('Error uploading library resource:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});


// Handle Upvote/Downvote logic
app.post('/api/library/:id/vote', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { type } = req.body; // 'upvote' or 'downvote'

  try {
    // Check existing interaction
    const existing = await pool.query(
      'SELECT id, interaction_type FROM library_interactions WHERE user_id = $1 AND resource_id = $2',
      [req.user.userId, id]
    );

    if (existing.rows.length > 0) {
      const currentType = existing.rows[0].interaction_type;

      if (currentType === type) {
        // Toggle OFF (remove vote)
        await pool.query('DELETE FROM library_interactions WHERE id = $1', [existing.rows[0].id]);
        return res.json({ success: true, action: 'removed' });
      } else {
        // Switch Vote (Up -> Down or Down -> Up)
        await pool.query(
          'UPDATE library_interactions SET interaction_type = $1 WHERE id = $2',
          [type, existing.rows[0].id]
        );
        return res.json({ success: true, action: 'switched' });
      }
    } else {
      // Create New Vote
      await pool.query(
        'INSERT INTO library_interactions (user_id, resource_id, interaction_type) VALUES ($1, $2, $3)',
        [req.user.userId, id, type]
      );
      return res.json({ success: true, action: 'added' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get Comments for a Resource
app.get('/api/library/:id/comments', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, u.full_name, u.profile_image_url,
      (SELECT COUNT(*) FROM library_comment_likes WHERE comment_id = c.id) as likes,
      EXISTS(SELECT 1 FROM library_comment_likes WHERE comment_id = c.id AND user_id = $1) as has_liked
      FROM library_comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.resource_id = $2
      ORDER BY c.created_at ASC
    `, [req.user.userId, req.params.id]);

    // Helper to nest comments (handled on frontend usually, but flat list is fine for now)
    res.json({ success: true, comments: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Post a Comment
app.post('/api/library/:id/comments', authMiddleware, async (req, res) => {
  const { content, parentId } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO library_comments (resource_id, user_id, content, parent_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.id, req.user.userId, content, parentId || null]
    );
    // Return with user info for immediate display
    const newComment = await pool.query(
      `SELECT c.*, u.full_name, u.profile_image_url, 0 as likes, false as has_liked
       FROM library_comments c JOIN users u ON c.user_id = u.id WHERE c.id = $1`,
      [result.rows[0].id]
    );
    res.json({ success: true, comment: newComment.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 4. TOGGLE BOOKMARK
app.post('/api/library/:id/bookmark', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const existing = await pool.query(
      'SELECT id FROM library_bookmarks WHERE user_id = $1 AND resource_id = $2',
      [req.user.userId, id]
    );

    if (existing.rows.length > 0) {
      await pool.query('DELETE FROM library_bookmarks WHERE id = $1', [existing.rows[0].id]);
      res.json({ success: true, action: 'removed', is_bookmarked: false });
    } else {
      await pool.query(
        'INSERT INTO library_bookmarks (user_id, resource_id) VALUES ($1, $2)',
        [req.user.userId, id]
      );
      res.json({ success: true, action: 'added', is_bookmarked: true });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 5. DELETE RESOURCE
app.delete('/api/library/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM library_resources WHERE id = $1 AND uploader_id = $2 RETURNING *',
      [req.params.id, req.user.userId]
    );
    if (result.rowCount === 0) return res.status(403).json({ success: false, message: "Unauthorized" });
    res.json({ success: true, message: "Resource deleted" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});// ============================================
// LIBRARY RESOURCES - FINAL SYNCED VERSION
// ============================================

// 1. GET ALL RESOURCES (Includes Upvote/Bookmark status)
app.get('/api/library', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lr.*, u.full_name as uploader_name,
        (SELECT COUNT(*) FROM library_interactions WHERE resource_id = lr.id AND interaction_type = 'upvote') as upvotes,
        EXISTS(SELECT 1 FROM library_interactions WHERE resource_id = lr.id AND user_id = $1 AND interaction_type = 'upvote') as has_upvoted,
        EXISTS(SELECT 1 FROM library_bookmarks WHERE resource_id = lr.id AND user_id = $1) as is_bookmarked
      FROM library_resources lr 
      JOIN users u ON lr.uploader_id = u.id 
      WHERE lr.is_public = true 
      ORDER BY lr.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, resources: result.rows });
  } catch (error) {
    console.error('Library Fetch Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 2. GET USER BOOKMARKS - FIXES THE 404 ERROR
// Note: This must be ABOVE /api/library/:id routes
app.get('/api/library/bookmarks', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT resource_id FROM library_bookmarks WHERE user_id = $1`,
      [req.user.userId]
    );
    res.json({ success: true, bookmarks: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 3. UPLOAD RESOURCE - UPDATED TO INCLUDE CATEGORY
app.post('/api/library', authMiddleware, documentUpload.single('file'), async (req, res) => {
  const { title, description, subject, category } = req.body;
  
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded' });

    // Upload to Supabase Storage (Bucket: library-resources)
    const fileUrl = await uploadToSupabase(req.file, 'library-resources', '');
    
    const result = await pool.query(
      `INSERT INTO library_resources 
       (uploader_id, title, description, subject, category, file_url, file_type, file_size) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.user.userId, title, description, subject, category || 'Lecture Notes', fileUrl, req.file.mimetype, req.file.size]
    );
    
    res.json({ success: true, resource: result.rows[0] });
  } catch (error) {
    console.error('Error uploading library resource:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 4. TOGGLE BOOKMARK
app.post('/api/library/:id/bookmark', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const existing = await pool.query(
      'SELECT id FROM library_bookmarks WHERE user_id = $1 AND resource_id = $2',
      [req.user.userId, id]
    );

    if (existing.rows.length > 0) {
      await pool.query('DELETE FROM library_bookmarks WHERE id = $1', [existing.rows[0].id]);
      res.json({ success: true, action: 'removed', is_bookmarked: false });
    } else {
      await pool.query(
        'INSERT INTO library_bookmarks (user_id, resource_id) VALUES ($1, $2)',
        [req.user.userId, id]
      );
      res.json({ success: true, action: 'added', is_bookmarked: true });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 5. DELETE RESOURCE
app.delete('/api/library/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM library_resources WHERE id = $1 AND uploader_id = $2 RETURNING *',
      [req.params.id, req.user.userId]
    );
    if (result.rowCount === 0) return res.status(403).json({ success: false, message: "Unauthorized" });
    res.json({ success: true, message: "Resource deleted" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 6. TOGGLE UPVOTE
app.post('/api/library/:id/upvote', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Check if upvote exists
    const existing = await pool.query(
      "SELECT id FROM library_interactions WHERE user_id = $1 AND resource_id = $2 AND interaction_type = 'upvote'",
      [req.user.userId, id]
    );

    if (existing.rows.length > 0) {
      // If exists, remove it (Toggle OFF)
      await pool.query(
        "DELETE FROM library_interactions WHERE id = $1",
        [existing.rows[0].id]
      );
      res.json({ success: true, action: 'removed' });
    } else {
      // If not, add it (Toggle ON)
      await pool.query(
        "INSERT INTO library_interactions (user_id, resource_id, interaction_type) VALUES ($1, $2, 'upvote')",
        [req.user.userId, id]
      );
      res.json({ success: true, action: 'added' });
    }
  } catch (error) {
    console.error('Upvote error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// ADD THIS ROUTE TO YOUR server.js FILE
// Place it right after the upvote route (around line 2267)
// ============================================

app.post('/api/library/:id/downvote', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Check if downvote exists
    const existing = await pool.query(
      "SELECT id FROM library_interactions WHERE user_id = $1 AND resource_id = $2 AND interaction_type = 'downvote'",
      [req.user.userId, id]
    );

    if (existing.rows.length > 0) {
      // If exists, remove it (Toggle OFF)
      await pool.query(
        "DELETE FROM library_interactions WHERE id = $1",
        [existing.rows[0].id]
      );
      res.json({ success: true, action: 'removed' });
    } else {
      // If not, add it (Toggle ON)
      // First, remove any existing upvote to prevent both
      await pool.query(
        "DELETE FROM library_interactions WHERE user_id = $1 AND resource_id = $2 AND interaction_type = 'upvote'",
        [req.user.userId, id]
      );
      
      await pool.query(
        "INSERT INTO library_interactions (user_id, resource_id, interaction_type) VALUES ($1, $2, 'downvote')",
        [req.user.userId, id]
      );
      res.json({ success: true, action: 'added' });
    }
  } catch (error) {
    console.error('Downvote error:', error);
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
// Add this after the POST /api/study-groups route
app.post('/api/study-groups/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  
  try {
    const groupCheck = await pool.query('SELECT * FROM study_groups WHERE id = $1', [id]);
    if (groupCheck.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Group not found' });
    }
    
    // Check if already a member
    const memberCheck = await pool.query(
      'SELECT * FROM study_group_members WHERE group_id = $1 AND user_id = $2',
      [id, req.user.userId]
    );

    if (memberCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'You are already a member of this group' });
    }

    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id) VALUES ($1, $2)',
      [id, req.user.userId]
    );
    
    res.json({ success: true, message: 'Joined study group successfully' });
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

// ============================================
// COMPLETE ENHANCED TIMETABLE BACKEND - ALL FEATURES
// Copy this entire file content into your server.js
// Place after your existing routes (around line 2420)
// ============================================

// ============================================
// PROGRAMS & AUTOMATIC IMPORT
// ============================================

app.get('/api/programs', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT p.*, COUNT(mt.id) as course_count
       FROM programs p
       LEFT JOIN master_timetables mt ON p.id = mt.program_id
       GROUP BY p.id
       ORDER BY p.institution, p.program_name`
    );
    res.json({ success: true, programs: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/programs', authMiddleware, async (req, res) => {
  const { institutionName, programCode, programName, department, yearLevel, semester } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO programs (institution, program_code, program_name, department, year_level, semester)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [institutionName, programCode, programName, department, yearLevel, semester]
    );
    res.json({ success: true, program: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/programs/:programId/courses', authMiddleware, async (req, res) => {
  const { programId } = req.params;
  
  try {
    const result = await pool.query(
      'SELECT * FROM master_timetables WHERE program_id = $1 ORDER BY day_of_week, start_time',
      [programId]
    );
    res.json({ success: true, courses: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/programs/:programId/courses', authMiddleware, async (req, res) => {
  const { programId } = req.params;
  const { courses } = req.body;
  
  try {
    const insertPromises = courses.map(course => 
      pool.query(
        `INSERT INTO master_timetables 
         (program_id, course_code, course_name, day_of_week, start_time, end_time, room_number, building, instructor)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [programId, course.course_code, course.course_name, course.day_of_week, 
         course.start_time, course.end_time, course.room_number, course.building, course.instructor]
      )
    );
    
    await Promise.all(insertPromises);
    res.json({ success: true, message: 'Courses added to program' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/timetable/import-from-program', authMiddleware, async (req, res) => {
  const { programId, selectedCourses } = req.body;
  
  try {
    await pool.query(
      'INSERT INTO student_programs (user_id, program_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.userId, programId]
    );
    
    const result = await pool.query(
      `SELECT * FROM master_timetables 
       WHERE program_id = $1 AND course_code = ANY($2)`,
      [programId, selectedCourses]
    );
    
    const insertPromises = result.rows.map(course =>
      pool.query(
        `INSERT INTO timetables 
         (user_id, title, day_of_week, start_time, end_time, course_code, instructor, 
          building, room_number, color, location, notification_enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING *`,
        [req.user.userId, course.course_name, course.day_of_week, course.start_time, 
         course.end_time, course.course_code, course.instructor, course.building, 
         course.room_number, '#3B82F6', course.building + ' ' + course.room_number, true]
      )
    );
    
    const imported = await Promise.all(insertPromises);
    
    // Check for clashes
    const clashes = await pool.query(
      `SELECT t1.id as entry1_id, t1.title as title1, t1.start_time as start1, t1.end_time as end1,
              t2.id as entry2_id, t2.title as title2, t2.start_time as start2, t2.end_time as end2,
              t1.day_of_week
       FROM timetables t1
       JOIN timetables t2 ON t1.day_of_week = t2.day_of_week AND t1.id < t2.id
       WHERE t1.user_id = $1 AND t2.user_id = $1
       AND (t1.start_time < t2.end_time AND t1.end_time > t2.start_time)`,
      [req.user.userId]
    );
    
    for (const clash of clashes.rows) {
      await pool.query(
        `INSERT INTO timetable_clashes (user_id, entry1_id, entry2_id, clash_type)
         VALUES ($1, $2, $3, 'overlap')
         ON CONFLICT DO NOTHING`,
        [req.user.userId, clash.entry1_id, clash.entry2_id]
      );
    }
    
    res.json({ 
      success: true, 
      imported: imported.length,
      clashes: clashes.rows
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// CLASH DETECTION
// ============================================

app.get('/api/timetable/clashes', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT tc.*, 
              t1.title as class1_title, t1.start_time as class1_start, t1.end_time as class1_end,
              t2.title as class2_title, t2.start_time as class2_start, t2.end_time as class2_end,
              t1.day_of_week
       FROM timetable_clashes tc
       JOIN timetables t1 ON tc.entry1_id = t1.id
       JOIN timetables t2 ON tc.entry2_id = t2.id
       WHERE tc.user_id = $1 AND tc.resolved = false`,
      [req.user.userId]
    );
    res.json({ success: true, clashes: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/timetable/clashes/:clashId/resolve', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'UPDATE timetable_clashes SET resolved = true WHERE id = $1 AND user_id = $2',
      [req.params.clashId, req.user.userId]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// CLASSROOM LOCATIONS & MAPS
// ============================================

app.post('/api/classroom-locations', authMiddleware, async (req, res) => {
  const { building, roomNumber, locationName, lat, lng, notes, isPublic } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO classroom_locations 
       (user_id, building, room_number, location_name, location_lat, location_lng, notes, is_public)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (user_id, building, room_number) 
       DO UPDATE SET location_name = $4, location_lat = $5, location_lng = $6, notes = $7, is_public = $8
       RETURNING *`,
      [req.user.userId, building, roomNumber, locationName, lat, lng, notes, isPublic]
    );
    res.json({ success: true, location: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/classroom-locations', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT cl.*, u.full_name as created_by_name
       FROM classroom_locations cl
       JOIN users u ON cl.user_id = u.id
       WHERE cl.user_id = $1 OR cl.is_public = true
       ORDER BY cl.building, cl.room_number`,
      [req.user.userId]
    );
    res.json({ success: true, locations: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/classroom-locations/:building/:room', authMiddleware, async (req, res) => {
  const { building, room } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT * FROM classroom_locations 
       WHERE (user_id = $1 OR is_public = true)
       AND building = $2 AND room_number = $3
       LIMIT 1`,
      [req.user.userId, building, room]
    );
    
    if (result.rows.length > 0) {
      res.json({ success: true, location: result.rows[0] });
    } else {
      res.json({ success: false, message: 'Location not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// ASSIGNMENTS
// ============================================

app.post('/api/assignments', authMiddleware, async (req, res) => {
  const { courseCode, title, description, dueDate, submissionPlace, submissionType, weight, notificationHoursBefore } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO assignments 
       (user_id, course_code, title, description, due_date, submission_place, 
        submission_type, weight, notification_hours_before)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [req.user.userId, courseCode, title, description, dueDate, submissionPlace, 
       submissionType, weight, notificationHoursBefore || 24]
    );
    
    const assignment = result.rows[0];
    const notificationTime = new Date(dueDate);
    notificationTime.setHours(notificationTime.getHours() - (notificationHoursBefore || 24));
    
    await pool.query(
      `INSERT INTO notifications 
       (user_id, notification_type, reference_id, title, message, scheduled_time)
       VALUES ($1, 'assignment', $2, $3, $4, $5)`,
      [
        req.user.userId,
        assignment.id,
        `Assignment Due: ${title}`,
        `Your assignment "${title}" for ${courseCode} is due in ${notificationHoursBefore || 24} hours!`,
        notificationTime
      ]
    );
    
    res.json({ success: true, assignment: assignment });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/assignments', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `UPDATE assignments SET status = 'overdue'
       WHERE due_date < NOW() AND status = 'pending' AND user_id = $1`,
      [req.user.userId]
    );
    
    const result = await pool.query(
      `SELECT * FROM assignments 
       WHERE user_id = $1 
       ORDER BY due_date ASC`,
      [req.user.userId]
    );
    res.json({ success: true, assignments: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.patch('/api/assignments/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  try {
    const fields = [];
    const values = [];
    let paramCount = 1;
    
    Object.keys(updates).forEach(key => {
      if (updates[key] !== undefined) {
        fields.push(`${key} = $${paramCount}`);
        values.push(updates[key]);
        paramCount++;
      }
    });
    
    values.push(id);
    values.push(req.user.userId);
    
    const result = await pool.query(
      `UPDATE assignments SET ${fields.join(', ')} 
       WHERE id = $${paramCount} AND user_id = $${paramCount + 1}
       RETURNING *`,
      values
    );
    
    res.json({ success: true, assignment: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/assignments/:id/submit', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE assignments 
       SET status = 'submitted', submitted_at = NOW()
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [req.params.id, req.user.userId]
    );
    res.json({ success: true, assignment: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/assignments/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM assignments WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.userId]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/assignments/cleanup', async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM assignments 
       WHERE due_date < NOW() - INTERVAL '1 hour'
       AND status != 'submitted'
       RETURNING id`
    );
    res.json({ success: true, deleted: result.rows.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// SCHOOL EVENTS
// ============================================

app.get('/api/school-events', authMiddleware, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT institution FROM users WHERE id = $1',
      [req.user.userId]
    );
    
    const institution = userResult.rows[0]?.institution;
    
    const result = await pool.query(
      `SELECT se.*, u.full_name as creator_name
       FROM school_events se
       LEFT JOIN users u ON se.created_by = u.id
       WHERE se.institution = $1
       AND se.end_date >= NOW()
       ORDER BY se.start_date ASC`,
      [institution]
    );
    
    res.json({ success: true, events: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/school-events', authMiddleware, async (req, res) => {
  const { eventType, title, description, startDate, endDate, location, lat, lng, isMandatory, notifyDaysBefore } = req.body;
  
  try {
    const userResult = await pool.query(
      'SELECT institution FROM users WHERE id = $1',
      [req.user.userId]
    );
    
    const result = await pool.query(
      `INSERT INTO school_events 
       (institution, event_type, title, description, start_date, end_date, 
        location, location_lat, location_lng, is_mandatory, notify_days_before, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [userResult.rows[0].institution, eventType, title, description, startDate, endDate, 
       location, lat, lng, isMandatory, notifyDaysBefore, req.user.userId]
    );
    
    res.json({ success: true, event: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/school-events/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM school_events WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// EXAMS & COUNTDOWN
// ============================================

app.post('/api/exams', authMiddleware, async (req, res) => {
  const { courseCode, courseName, examDate, duration, location, roomNumber, examType, weight } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO exam_schedules 
       (user_id, course_code, course_name, exam_date, exam_duration, location, room_number, exam_type, weight)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [req.user.userId, courseCode, courseName, examDate, duration, location, roomNumber, examType, weight]
    );
    
    const exam = result.rows[0];
    
    // 60-day countdown
    const countdownDate = new Date(examDate);
    countdownDate.setDate(countdownDate.getDate() - 60);
    
    if (countdownDate > new Date()) {
      await pool.query(
        `INSERT INTO notifications 
         (user_id, notification_type, reference_id, title, message, scheduled_time)
         VALUES ($1, 'exam', $2, $3, $4, $5)`,
        [
          req.user.userId,
          exam.id,
          '60 Days Until Exam!',
          `Your ${courseCode} ${examType} exam is in 60 days. Time to start preparing!`,
          countdownDate
        ]
      );
    }
    
    // 7-day reminder
    const reminderDate = new Date(examDate);
    reminderDate.setDate(reminderDate.getDate() - 7);
    
    if (reminderDate > new Date()) {
      await pool.query(
        `INSERT INTO notifications 
         (user_id, notification_type, reference_id, title, message, scheduled_time)
         VALUES ($1, 'exam', $2, $3, $4, $5)`,
        [
          req.user.userId,
          exam.id,
          'Exam Next Week!',
          `Your ${courseCode} ${examType} is in 7 days. Final review time!`,
          reminderDate
        ]
      );
    }
    
    res.json({ success: true, exam: exam });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/exams', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT e.*, sp.id as study_plan_id, sp.progress_percentage
       FROM exam_schedules e
       LEFT JOIN study_plans sp ON e.id = sp.exam_id
       WHERE e.user_id = $1
       ORDER BY e.exam_date ASC`,
      [req.user.userId]
    );
    res.json({ success: true, exams: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/exams/countdown', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT *, 
              EXTRACT(EPOCH FROM (exam_date - NOW())) / 86400 as days_until
       FROM exam_schedules
       WHERE user_id = $1
       AND exam_date > NOW()
       ORDER BY exam_date ASC
       LIMIT 5`,
      [req.user.userId]
    );
    res.json({ success: true, exams: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/exams/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM exam_schedules WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.userId]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// STUDY PLANS
// ============================================

app.post('/api/exams/:examId/generate-study-plan', authMiddleware, async (req, res) => {
  const { examId } = req.params;
  const { topics, totalHours, startDate } = req.body;
  
  try {
    const examResult = await pool.query(
      'SELECT * FROM exam_schedules WHERE id = $1 AND user_id = $2',
      [examId, req.user.userId]
    );
    
    if (examResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Exam not found' });
    }
    
    const exam = examResult.rows[0];
    const examDate = new Date(exam.exam_date);
    const start = new Date(startDate || Date.now());
    const daysAvailable = Math.floor((examDate - start) / (1000 * 60 * 60 * 24));
    
    if (daysAvailable <= 0) {
      return res.status(400).json({ success: false, message: 'Exam date has passed' });
    }
    
    const dailyHours = Math.min(totalHours / daysAvailable, 8); // Cap at 8 hours per day
    
    const planResult = await pool.query(
      `INSERT INTO study_plans 
       (exam_id, user_id, total_study_hours, daily_study_hours, start_date, end_date, topics)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [examId, req.user.userId, totalHours, dailyHours, start, examDate, JSON.stringify(topics)]
    );
    
    const plan = planResult.rows[0];
    
    // Generate daily tasks
    const topicsArray = topics || [];
    const tasksPerDay = Math.max(1, Math.floor(topicsArray.length / daysAvailable));
    
    for (let day = 0; day < daysAvailable; day++) {
      const taskDate = new Date(start);
      taskDate.setDate(taskDate.getDate() + day);
      
      const topicIndex = Math.floor(day / daysAvailable * topicsArray.length);
      const topic = topicsArray[topicIndex] || topicsArray[topicsArray.length - 1];
      
      await pool.query(
        `INSERT INTO study_tasks 
         (study_plan_id, task_date, topic, duration_minutes)
         VALUES ($1, $2, $3, $4)`,
        [plan.id, taskDate, topic, dailyHours * 60]
      );
    }
    
    await pool.query(
      'UPDATE exam_schedules SET study_plan_generated = true WHERE id = $1',
      [examId]
    );
    
    res.json({ success: true, studyPlan: plan });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/exams/:examId/study-plan', authMiddleware, async (req, res) => {
  try {
    const planResult = await pool.query(
      `SELECT sp.*, e.course_code, e.course_name, e.exam_date
       FROM study_plans sp
       JOIN exam_schedules e ON sp.exam_id = e.id
       WHERE sp.exam_id = $1 AND sp.user_id = $2`,
      [req.params.examId, req.user.userId]
    );
    
    if (planResult.rows.length === 0) {
      return res.json({ success: false, message: 'No study plan found' });
    }
    
    const plan = planResult.rows[0];
    
    const tasksResult = await pool.query(
      `SELECT * FROM study_tasks 
       WHERE study_plan_id = $1 
       ORDER BY task_date, id`,
      [plan.id]
    );
    
    res.json({ 
      success: true, 
      studyPlan: plan,
      tasks: tasksResult.rows 
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/study-tasks/:taskId/complete', authMiddleware, async (req, res) => {
  const { notes } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE study_tasks st
       SET completed = true, completed_at = NOW(), notes = $1
       FROM study_plans sp
       WHERE st.id = $2 AND st.study_plan_id = sp.id AND sp.user_id = $3
       RETURNING st.*`,
      [notes, req.params.taskId, req.user.userId]
    );
    
    await pool.query(
      `UPDATE study_plans sp
       SET progress_percentage = (
         SELECT (COUNT(*) FILTER (WHERE completed = true)::DECIMAL / COUNT(*)) * 100
         FROM study_tasks
         WHERE study_plan_id = sp.id
       )
       WHERE id = (
         SELECT study_plan_id FROM study_tasks WHERE id = $1
       )`,
      [req.params.taskId]
    );
    
    res.json({ success: true, task: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// NOTIFICATIONS
// ============================================

app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM notifications
       WHERE user_id = $1
       AND scheduled_time <= NOW()
       ORDER BY scheduled_time DESC
       LIMIT 50`,
      [req.user.userId]
    );
    res.json({ success: true, notifications: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/notifications/unread-count', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND read = false',
      [req.user.userId]
    );
    res.json({ success: true, count: parseInt(result.rows[0].count) });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/notifications/:id/read', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'UPDATE notifications SET read = true, read_at = NOW() WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.userId]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/notifications/process', async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE notifications
       SET sent = true, sent_at = NOW()
       WHERE scheduled_time <= NOW()
       AND sent = false
       RETURNING *`
    );
    
    res.json({ success: true, processed: result.rows.length, notifications: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/timetable/setup-notifications', authMiddleware, async (req, res) => {
  try {
    const entries = await pool.query(
      'SELECT * FROM timetables WHERE user_id = $1 AND notification_enabled = true',
      [req.user.userId]
    );
    
    let scheduled = 0;
    
    for (const entry of entries.rows) {
      const now = new Date();
      const dayOfWeek = entry.day_of_week;
      const [hours, minutes] = entry.start_time.split(':');
      
      let nextDate = new Date();
      nextDate.setHours(hours, minutes, 0, 0);
      
      while (nextDate.getDay() !== dayOfWeek || nextDate <= now) {
        nextDate.setDate(nextDate.getDate() + 1);
      }
      
      const notificationTime = new Date(nextDate);
      notificationTime.setMinutes(notificationTime.getMinutes() - (entry.notification_minutes_before || 30));
      
      if (notificationTime > now) {
        await pool.query(
          `INSERT INTO notifications 
           (user_id, notification_type, reference_id, title, message, scheduled_time)
           VALUES ($1, 'class', $2, $3, $4, $5)
           ON CONFLICT DO NOTHING`,
          [
            req.user.userId,
            entry.id,
            `Class Starting Soon: ${entry.title}`,
            `Your ${entry.course_code || ''} class starts in ${entry.notification_minutes_before || 30} minutes at ${entry.location || 'campus'}`,
            notificationTime
          ]
        );
        scheduled++;
      }
    }
    
    res.json({ success: true, scheduled: scheduled });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// RIDESHARE
// ============================================

app.post('/api/rideshare', authMiddleware, async (req, res) => {
  const { destinationName, lat, lng, pickupTime, seatsAvailable, isDriver, notes } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO rideshare_requests 
       (user_id, destination_name, destination_lat, destination_lng, pickup_time, 
        seats_available, is_driver, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [req.user.userId, destinationName, lat, lng, pickupTime, seatsAvailable, isDriver, notes]
    );
    res.json({ success: true, request: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/rideshare', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT rr.*, u.full_name, u.phone
       FROM rideshare_requests rr
       JOIN users u ON rr.user_id = u.id
       WHERE rr.status = 'active'
       AND rr.pickup_time > NOW()
       ORDER BY rr.pickup_time ASC`
    );
    res.json({ success: true, requests: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.patch('/api/rideshare/:id/status', authMiddleware, async (req, res) => {
  const { status } = req.body;
  
  try {
    const result = await pool.query(
      'UPDATE rideshare_requests SET status = $1 WHERE id = $2 RETURNING *',
      [status, req.params.id]
    );
    res.json({ success: true, request: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// UPDATE EXISTING TIMETABLE ROUTE
// ============================================

app.patch('/api/timetable/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  try {
    const fields = [];
    const values = [];
    let paramCount = 1;
    
    Object.keys(updates).forEach(key => {
      if (updates[key] !== undefined) {
        fields.push(`${key} = $${paramCount}`);
        values.push(updates[key]);
        paramCount++;
      }
    });
    
    values.push(id);
    values.push(req.user.userId);
    
    const result = await pool.query(
      `UPDATE timetables SET ${fields.join(', ')} 
       WHERE id = $${paramCount} AND user_id = $${paramCount + 1}
       RETURNING *`,
      values
    );
    
    res.json({ success: true, entry: result.rows[0] });
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
    
    await pool.query(
      "UPDATE homework_help SET status = 'answered' WHERE id = $1 AND status = 'open'",
      [id]
    );
    
    res.json({ success: true, response: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add this before the POST /api/homework-help/:id/respond route
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

// ... existing imports ...
// Add lodash for easier data manipulation if not present: const _ = require('lodash');
// ============================================
// UNIVERSAL PDF PARSER - FIXED VERSION
// ============================================



app.post('/api/parse-timetable-pdf', authMiddleware, upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });

    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
    const base64Pdf = req.file.buffer.toString('base64');

    const prompt = `Analyze this university timetable. Extract all class sessions into a JSON array.
    Strictly use this format:
    {
      "course_code": "CS101",
      "course_name": "Intro to Computing",
      "day_of_week": 1, (1 for Monday, 2 for Tuesday, etc.)
      "start_time": "HH:MM", (24h format, e.g. "08:30")
      "end_time": "HH:MM",
      "location": "Room 302",
      "instructor": "Dr. Name"
    }`;

    const result = await model.generateContent([
      { text: prompt },
      { inlineData: { data: base64Pdf, mimeType: "application/pdf" } }
    ]);

    const text = result.response.text().replace(/```json|```/g, '');
    const courses = JSON.parse(text);

    // Safety formatting to prevent frontend crashes
    const formatted = courses.map((c, i) => ({
      ...c,
      id: `gemini-${Date.now()}-${i}`,
      start_time: String(c.start_time || "08:00"),
      end_time: String(c.end_time || "09:00"),
      checked: true
    }));

    res.json({ success: true, courses: formatted });
  } catch (error) {
    console.error('Gemini Error:', error);
    res.status(500).json({ success: false, error: 'AI failed to parse PDF' });
  }
});
// ============================================
// CREATE/GET PROGRAM (Universal)
// ============================================
app.post('/api/programs', authMiddleware, async (req, res) => {
  try {
    const { programName, programCode, department, yearLevel, semester } = req.body;
    
    const result = await pool.query(
      `INSERT INTO programs (user_id, program_name, program_code, department, year_level, semester)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [req.user.id, programName, programCode, department, yearLevel, semester]
    );
    
    res.json({ success: true, program: result.rows[0] });
  } catch (error) {
    console.error('Create program error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/programs', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM programs WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ success: true, programs: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// BULK UPLOAD COURSES
// ============================================
app.post('/api/program-courses/bulk', authMiddleware, async (req, res) => {
  try {
    const { programId, courses } = req.body;
    
    if (!courses || courses.length === 0) {
      return res.status(400).json({ success: false, error: 'No courses provided' });
    }
    
    // Insert all courses
    for (const course of courses) {
      await pool.query(
        `INSERT INTO program_courses 
        (program_id, course_code, course_name, day_of_week, start_time, end_time, 
         building, room_number, instructor, year_level)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          programId,
          course.course_code,
          course.course_name || course.course_code,
          course.day_of_week,
          course.start_time,
          course.end_time,
          course.building,
          course.room_number,
          course.instructor,
          course.year_level
        ]
      );
    }
    
    res.json({ success: true, imported: courses.length });
  } catch (error) {
    console.error('Bulk upload error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// GET PROGRAM COURSES
// ============================================
app.get('/api/programs/:id/courses', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM program_courses WHERE program_id = $1 ORDER BY day_of_week, start_time',
      [req.params.id]
    );
    res.json({ success: true, courses: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Route not found',
    path: req.path 
  });
});

app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ 
      success: false, 
      message: 'File too large. Maximum size: 5MB for images, 50MB for documents' 
    });
  }
  
  if (err.message && err.message.includes('Only image files')) {
    return res.status(400).json({ 
      success: false, 
      message: err.message 
    });
  }
  
  if (err.message && err.message.includes('Only document files')) {
    return res.status(400).json({ 
      success: false, 
      message: err.message 
    });
  }
  
  res.status(500).json({ 
    success: false, 
    message: err.message || 'Internal server error'
  });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`💾 Storage: Supabase Storage`);
  console.log(`📊 Database: PostgreSQL (Supabase)`);
  console.log(`\n✅ Initialize database at: /api/init-db`);
});

