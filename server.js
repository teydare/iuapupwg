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
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const PORT = process.env.PORT || 5000;

// Groq for PDF parsing (free, fast, no quota issues)
const GROQ_API_KEY = process.env.GROQ_API_KEY || null;
if (GROQ_API_KEY) console.log('✅ Groq ready');
else console.log('⚠️  No GROQ_API_KEY — PDF parsing will use pattern-matching fallback');
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
// allowlist + options for CORS
const allowedOrigins = [
  process.env.FRONTEND_URL,
  'https://fuddystudy.vercel.app',
  'http://localhost:3000'
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    // allow non-browser requests (e.g. curl, server-to-server) with no origin
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','Accept','X-Requested-With']
}));

// Ensure preflight requests are answered
app.options('*', cors());  
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
  building VARCHAR(100),
  room_number VARCHAR(50),
  notes TEXT,
  color VARCHAR(7) DEFAULT '#3B82F6',
  notification_enabled BOOLEAN DEFAULT true,
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
  is_expert_response BOOLEAN DEFAULT false,
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

-- Programs (timetable programs per user)
CREATE TABLE IF NOT EXISTS programs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  program_name VARCHAR(255) NOT NULL,
  program_code VARCHAR(50),
  department VARCHAR(100),
  year_level INTEGER,
  semester VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Program courses
CREATE TABLE IF NOT EXISTS program_courses (
  id SERIAL PRIMARY KEY,
  program_id INTEGER REFERENCES programs(id) ON DELETE CASCADE,
  course_code VARCHAR(50) NOT NULL,
  course_name VARCHAR(255),
  day_of_week INTEGER,
  start_time TIME,
  end_time TIME,
  location VARCHAR(255),
  building VARCHAR(100),
  room_number VARCHAR(50),
  instructor VARCHAR(255),
  year_level INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_programs_user ON programs(user_id);
CREATE INDEX IF NOT EXISTS idx_program_courses_program ON program_courses(program_id);

-- Student Programs (links a user to a program they enrolled in)
CREATE TABLE IF NOT EXISTS student_programs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  program_id INTEGER REFERENCES programs(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, program_id)
);

-- Timetable Clashes
CREATE TABLE IF NOT EXISTS timetable_clashes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  entry1_id INTEGER REFERENCES timetables(id) ON DELETE CASCADE,
  entry2_id INTEGER REFERENCES timetables(id) ON DELETE CASCADE,
  clash_type VARCHAR(50) DEFAULT 'overlap',
  resolved BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(entry1_id, entry2_id)
);

-- Assignments
CREATE TABLE IF NOT EXISTS assignments (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  course_code VARCHAR(50),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  due_date TIMESTAMP,
  submission_place VARCHAR(255),
  submission_type VARCHAR(50) DEFAULT 'online',
  weight DECIMAL(5,2),
  notification_hours_before INTEGER DEFAULT 24,
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Exam Schedules
CREATE TABLE IF NOT EXISTS exam_schedules (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  course_code VARCHAR(50),
  course_name VARCHAR(255),
  exam_date TIMESTAMP,
  exam_duration INTEGER DEFAULT 120,
  location VARCHAR(255),
  room_number VARCHAR(50),
  exam_type VARCHAR(50) DEFAULT 'final',
  weight DECIMAL(5,2),
  study_plan_generated BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Study Plans
CREATE TABLE IF NOT EXISTS study_plans (
  id SERIAL PRIMARY KEY,
  exam_id INTEGER REFERENCES exam_schedules(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  total_study_hours DECIMAL(6,2),
  daily_study_hours DECIMAL(5,2),
  start_date DATE,
  end_date DATE,
  topics JSONB,
  progress_percentage DECIMAL(5,2) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Study Tasks
CREATE TABLE IF NOT EXISTS study_tasks (
  id SERIAL PRIMARY KEY,
  study_plan_id INTEGER REFERENCES study_plans(id) ON DELETE CASCADE,
  task_date DATE,
  topic TEXT,
  duration_minutes INTEGER DEFAULT 60,
  completed BOOLEAN DEFAULT false,
  completed_at TIMESTAMP,
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  notification_type VARCHAR(50),
  reference_id INTEGER,
  title VARCHAR(255),
  message TEXT,
  scheduled_time TIMESTAMP,
  read BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- School Events
CREATE TABLE IF NOT EXISTS school_events (
  id SERIAL PRIMARY KEY,
  institution VARCHAR(255),
  event_type VARCHAR(50),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  start_date TIMESTAMP,
  end_date TIMESTAMP,
  location VARCHAR(255),
  location_lat DECIMAL(10,8),
  location_lng DECIMAL(11,8),
  is_mandatory BOOLEAN DEFAULT false,
  notify_days_before INTEGER DEFAULT 1,
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Rideshare Requests
CREATE TABLE IF NOT EXISTS rideshare_requests (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  destination_name VARCHAR(255),
  destination_lat DECIMAL(10,8),
  destination_lng DECIMAL(11,8),
  pickup_time TIMESTAMP,
  seats_available INTEGER DEFAULT 3,
  is_driver BOOLEAN DEFAULT true,
  notes TEXT,
  status VARCHAR(50) DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assignments_user ON assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_exam_schedules_user ON exam_schedules(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_study_plans_exam ON study_plans(exam_id);
CREATE INDEX IF NOT EXISTS idx_study_tasks_plan ON study_tasks(study_plan_id);
CREATE INDEX IF NOT EXISTS idx_rideshare_status ON rideshare_requests(status);
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

app.post('/api/auth/onboarding', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { programme, year, subjects, study_style, study_times, goals } = req.body;

  try {
    await pool.query(
      `UPDATE users SET
         programme     = $1,
         year_of_study = $2,
         subjects      = $3,
         study_style   = $4,
         study_times   = $5,
         goals         = $6,
         onboarded_at  = NOW(),
         updated_at    = NOW()
       WHERE id = $7`,
      [
        programme || null,
        year      || null,
        subjects  || [],
        study_style || null,
        study_times || [],
        goals     || [],
        userId,
      ]
    );
    res.json({ success: true, message: 'Profile saved' });
  } catch (err) {
    console.error('Onboarding save error:', err);
    res.status(500).json({ success: false, message: 'Failed to save profile' });
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
  const creatorId = req.user.userId;
  const { name, description, subject, program, maxMembers, isPrivate, study_mode, year_filter } = req.body;

  if (!name) return res.status(400).json({ success: false, message: 'Group name is required' });

  try {
    const result = await pool.query(
      `INSERT INTO study_groups
         (creator_id, name, description, subject, program, max_members, is_private, study_mode, year_filter)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [creatorId, name, description || null, subject || null, program || null,
       maxMembers || 50, isPrivate || false, study_mode || 'social', year_filter || null]
    );
    const group = result.rows[0];
    // Creator joins automatically as admin
    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id, role) VALUES ($1,$2,$3)',
      [group.id, creatorId, 'admin']
    );
    res.json({ success: true, group });
  } catch (err) {
    console.error('Create group error:', err);
    res.status(500).json({ success: false, message: 'Failed to create group' });
  }
});

// ── 4. UPDATED: GET /api/study-groups ────────────────────────
// Replaces the existing route — includes program, study_mode, active_session_count
app.get('/api/study-groups', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         sg.*,
         u.full_name AS creator_name,
         COUNT(DISTINCT sgm.id)::int AS member_count,
         COUNT(DISTINCT ss.id)::int  AS active_session_count
       FROM study_groups sg
       LEFT JOIN users u             ON u.id = sg.creator_id
       LEFT JOIN study_group_members sgm ON sgm.group_id = sg.id
       LEFT JOIN study_sessions ss   ON ss.group_id = sg.id AND ss.status = 'active'
       WHERE sg.is_private = false
       GROUP BY sg.id, u.full_name
       ORDER BY active_session_count DESC, member_count DESC, sg.created_at DESC`
    );
    res.json({ success: true, groups: result.rows });
  } catch (err) {
    console.error('Get groups error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch groups' });
  }
});

// ── 5. GET /api/study-groups/my ─────────────────────────────
app.get('/api/study-groups/my', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  try {
    const result = await pool.query(
      `SELECT
         sg.*,
         u.full_name AS creator_name,
         COUNT(DISTINCT sgm2.id)::int AS member_count,
         COUNT(DISTINCT ss.id)::int   AS active_session_count,
         mym.role
       FROM study_groups sg
       JOIN study_group_members mym  ON mym.group_id = sg.id AND mym.user_id = $1
       LEFT JOIN users u             ON u.id = sg.creator_id
       LEFT JOIN study_group_members sgm2 ON sgm2.group_id = sg.id
       LEFT JOIN study_sessions ss   ON ss.group_id = sg.id AND ss.status = 'active'
       GROUP BY sg.id, u.full_name, mym.role
       ORDER BY sg.created_at DESC`,
      [userId]
    );
    res.json({ success: true, groups: result.rows });
  } catch (err) {
    console.error('Get my groups error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch groups' });
  }
});

// ── 6. POST /api/study-groups/:id/leave ─────────────────────
app.post('/api/study-groups/:id/leave', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    // End session first
    await pool.query(
      `UPDATE study_sessions SET status='ended', ended_at=NOW() WHERE group_id=$1 AND user_id=$2 AND status='active'`,
      [id, userId]
    );
    await pool.query('DELETE FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Leave group error:', err);
    res.status(500).json({ success: false, message: 'Failed to leave group' });
  }
});

// ── 7. GET /api/study-groups/:id/members ────────────────────
app.get('/api/study-groups/:id/members', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT
         u.id, u.full_name, u.institution, u.profile_image_url,
         sgm.role, sgm.joined_at,
         CASE WHEN ss.id IS NOT NULL THEN true ELSE false END AS is_active
       FROM study_group_members sgm
       JOIN users u ON u.id = sgm.user_id
       LEFT JOIN study_sessions ss
         ON ss.group_id = $1 AND ss.user_id = u.id AND ss.status = 'active'
       WHERE sgm.group_id = $1
       ORDER BY is_active DESC, sgm.joined_at ASC`,
      [id]
    );
    res.json({ success: true, members: result.rows });
  } catch (err) {
    console.error('Get members error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch members' });
  }
});

// ── 8. GET /api/study-groups/:id/chat ───────────────────────
app.get('/api/study-groups/:id/chat', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    // Verify membership
    const mem = await pool.query('SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    if (mem.rows.length === 0) return res.status(403).json({ success: false, message: 'Not a member' });

    const result = await pool.query(
      `SELECT cm.id, cm.message, cm.created_at, cm.sender_id, u.full_name AS sender_name
       FROM chat_messages cm
       JOIN users u ON u.id = cm.sender_id
       WHERE cm.group_id = $1
       ORDER BY cm.created_at ASC
       LIMIT 100`,
      [id]
    );
    res.json({ success: true, messages: result.rows });
  } catch (err) {
    console.error('Get chat error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch chat' });
  }
});

// ── 9. POST /api/study-groups/:id/chat ──────────────────────
app.post('/api/study-groups/:id/chat', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ success: false, message: 'Message required' });
  try {
    const mem = await pool.query('SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    if (mem.rows.length === 0) return res.status(403).json({ success: false, message: 'Not a member' });

    await pool.query(
      'INSERT INTO chat_messages (sender_id, group_id, message) VALUES ($1,$2,$3)',
      [userId, id, message.trim()]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Send chat error:', err);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// ── 10. GET /api/study-groups/:id/goals ─────────────────────
app.get('/api/study-groups/:id/goals', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT g.*, u.full_name AS creator_name, uc.full_name AS completed_by_name
       FROM session_goals g
       JOIN users u ON u.id = g.created_by
       LEFT JOIN users uc ON uc.id = g.completed_by
       WHERE g.group_id = $1 AND g.goal_date = CURRENT_DATE
       ORDER BY g.created_at ASC`,
      [id]
    );
    res.json({ success: true, goals: result.rows });
  } catch (err) {
    console.error('Get goals error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch goals' });
  }
});

// ── 11. POST /api/study-groups/:id/goals ────────────────────
app.post('/api/study-groups/:id/goals', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  const { goal_text } = req.body;
  if (!goal_text?.trim()) return res.status(400).json({ success: false, message: 'Goal text required' });
  try {
    const mem = await pool.query('SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    if (mem.rows.length === 0) return res.status(403).json({ success: false, message: 'Not a member' });

    await pool.query(
      'INSERT INTO session_goals (group_id, created_by, goal_text) VALUES ($1,$2,$3)',
      [id, userId, goal_text.trim()]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Add goal error:', err);
    res.status(500).json({ success: false, message: 'Failed to add goal' });
  }
});

// ── 12. PATCH /api/study-groups/:id/goals/:goalId ───────────
app.patch('/api/study-groups/:id/goals/:goalId', authMiddleware, async (req, res) => {
  const { goalId } = req.params;
  const userId      = req.user.userId;
  const { completed } = req.body;
  try {
    await pool.query(
      `UPDATE session_goals SET
         completed    = $1,
         completed_by = $2,
         completed_at = $3
       WHERE id = $4`,
      [completed, completed ? userId : null, completed ? new Date() : null, goalId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Toggle goal error:', err);
    res.status(500).json({ success: false, message: 'Failed to update goal' });
  }
});

// ── 13. DELETE /api/study-groups/:id/goals/:goalId ──────────
app.delete('/api/study-groups/:id/goals/:goalId', authMiddleware, async (req, res) => {
  const { goalId } = req.params;
  const userId      = req.user.userId;
  try {
    await pool.query(
      'DELETE FROM session_goals WHERE id=$1 AND created_by=$2',
      [goalId, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Delete goal error:', err);
    res.status(500).json({ success: false, message: 'Failed to delete goal' });
  }
});

// ── 14. GET /api/study-groups/:id/session ───────────────────
app.get('/api/study-groups/:id/session', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    const activeCount = await pool.query(
      `SELECT COUNT(*)::int AS count FROM study_sessions WHERE group_id=$1 AND status='active'`,
      [id]
    );
    const userSess = await pool.query(
      `SELECT id FROM study_sessions WHERE group_id=$1 AND user_id=$2 AND status='active'`,
      [id, userId]
    );
    res.json({
      success: true,
      session: {
        active_count:      activeCount.rows[0].count,
        is_active_member:  userSess.rows.length > 0,
      },
    });
  } catch (err) {
    console.error('Get session error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch session' });
  }
});

// ── 15. POST /api/study-groups/:id/session/start ────────────
app.post('/api/study-groups/:id/session/start', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    const mem = await pool.query('SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    if (mem.rows.length === 0) return res.status(403).json({ success: false, message: 'Not a member' });

    await pool.query(
      `INSERT INTO study_sessions (group_id, user_id, status)
       VALUES ($1,$2,'active')
       ON CONFLICT (group_id, user_id, status) DO NOTHING`,
      [id, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Start session error:', err);
    res.status(500).json({ success: false, message: 'Failed to start session' });
  }
});

// ── 16. POST /api/study-groups/:id/session/end ──────────────
app.post('/api/study-groups/:id/session/end', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    await pool.query(
      `UPDATE study_sessions SET status='ended', ended_at=NOW()
       WHERE group_id=$1 AND user_id=$2 AND status='active'`,
      [id, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('End session error:', err);
    res.status(500).json({ success: false, message: 'Failed to end session' });
  }
});app.post('/api/study-groups', authMiddleware, async (req, res) => {
  const creatorId = req.user.userId;
  const { name, description, subject, program, maxMembers, isPrivate, study_mode, year_filter } = req.body;

  if (!name) return res.status(400).json({ success: false, message: 'Group name is required' });

  try {
    const result = await pool.query(
      `INSERT INTO study_groups
         (creator_id, name, description, subject, program, max_members, is_private, study_mode, year_filter)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [creatorId, name, description || null, subject || null, program || null,
       maxMembers || 50, isPrivate || false, study_mode || 'social', year_filter || null]
    );
    const group = result.rows[0];
    // Creator joins automatically as admin
    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id, role) VALUES ($1,$2,$3)',
      [group.id, creatorId, 'admin']
    );
    res.json({ success: true, group });
  } catch (err) {
    console.error('Create group error:', err);
    res.status(500).json({ success: false, message: 'Failed to create group' });
  }
});

// ── 4. UPDATED: GET /api/study-groups ────────────────────────
// Replaces the existing route — includes program, study_mode, active_session_count
app.get('/api/study-groups', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         sg.*,
         u.full_name AS creator_name,
         COUNT(DISTINCT sgm.id)::int AS member_count,
         COUNT(DISTINCT ss.id)::int  AS active_session_count
       FROM study_groups sg
       LEFT JOIN users u             ON u.id = sg.creator_id
       LEFT JOIN study_group_members sgm ON sgm.group_id = sg.id
       LEFT JOIN study_sessions ss   ON ss.group_id = sg.id AND ss.status = 'active'
       WHERE sg.is_private = false
       GROUP BY sg.id, u.full_name
       ORDER BY active_session_count DESC, member_count DESC, sg.created_at DESC`
    );
    res.json({ success: true, groups: result.rows });
  } catch (err) {
    console.error('Get groups error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch groups' });
  }
});

// ── 5. GET /api/study-groups/my ─────────────────────────────
app.get('/api/study-groups/my', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  try {
    const result = await pool.query(
      `SELECT
         sg.*,
         u.full_name AS creator_name,
         COUNT(DISTINCT sgm2.id)::int AS member_count,
         COUNT(DISTINCT ss.id)::int   AS active_session_count,
         mym.role
       FROM study_groups sg
       JOIN study_group_members mym  ON mym.group_id = sg.id AND mym.user_id = $1
       LEFT JOIN users u             ON u.id = sg.creator_id
       LEFT JOIN study_group_members sgm2 ON sgm2.group_id = sg.id
       LEFT JOIN study_sessions ss   ON ss.group_id = sg.id AND ss.status = 'active'
       GROUP BY sg.id, u.full_name, mym.role
       ORDER BY sg.created_at DESC`,
      [userId]
    );
    res.json({ success: true, groups: result.rows });
  } catch (err) {
    console.error('Get my groups error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch groups' });
  }
});

// ── 6. POST /api/study-groups/:id/leave ─────────────────────
app.post('/api/study-groups/:id/leave', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    // End session first
    await pool.query(
      `UPDATE study_sessions SET status='ended', ended_at=NOW() WHERE group_id=$1 AND user_id=$2 AND status='active'`,
      [id, userId]
    );
    await pool.query('DELETE FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Leave group error:', err);
    res.status(500).json({ success: false, message: 'Failed to leave group' });
  }
});

// ── 7. GET /api/study-groups/:id/members ────────────────────
app.get('/api/study-groups/:id/members', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT
         u.id, u.full_name, u.institution, u.profile_image_url,
         sgm.role, sgm.joined_at,
         CASE WHEN ss.id IS NOT NULL THEN true ELSE false END AS is_active
       FROM study_group_members sgm
       JOIN users u ON u.id = sgm.user_id
       LEFT JOIN study_sessions ss
         ON ss.group_id = $1 AND ss.user_id = u.id AND ss.status = 'active'
       WHERE sgm.group_id = $1
       ORDER BY is_active DESC, sgm.joined_at ASC`,
      [id]
    );
    res.json({ success: true, members: result.rows });
  } catch (err) {
    console.error('Get members error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch members' });
  }
});

// ── 8. GET /api/study-groups/:id/chat ───────────────────────
app.get('/api/study-groups/:id/chat', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    // Verify membership
    const mem = await pool.query('SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    if (mem.rows.length === 0) return res.status(403).json({ success: false, message: 'Not a member' });

    const result = await pool.query(
      `SELECT cm.id, cm.message, cm.created_at, cm.sender_id, u.full_name AS sender_name
       FROM chat_messages cm
       JOIN users u ON u.id = cm.sender_id
       WHERE cm.group_id = $1
       ORDER BY cm.created_at ASC
       LIMIT 100`,
      [id]
    );
    res.json({ success: true, messages: result.rows });
  } catch (err) {
    console.error('Get chat error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch chat' });
  }
});

// ── 9. POST /api/study-groups/:id/chat ──────────────────────
app.post('/api/study-groups/:id/chat', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ success: false, message: 'Message required' });
  try {
    const mem = await pool.query('SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    if (mem.rows.length === 0) return res.status(403).json({ success: false, message: 'Not a member' });

    await pool.query(
      'INSERT INTO chat_messages (sender_id, group_id, message) VALUES ($1,$2,$3)',
      [userId, id, message.trim()]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Send chat error:', err);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// ── 10. GET /api/study-groups/:id/goals ─────────────────────
app.get('/api/study-groups/:id/goals', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT g.*, u.full_name AS creator_name, uc.full_name AS completed_by_name
       FROM session_goals g
       JOIN users u ON u.id = g.created_by
       LEFT JOIN users uc ON uc.id = g.completed_by
       WHERE g.group_id = $1 AND g.goal_date = CURRENT_DATE
       ORDER BY g.created_at ASC`,
      [id]
    );
    res.json({ success: true, goals: result.rows });
  } catch (err) {
    console.error('Get goals error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch goals' });
  }
});

// ── 11. POST /api/study-groups/:id/goals ────────────────────
app.post('/api/study-groups/:id/goals', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  const { goal_text } = req.body;
  if (!goal_text?.trim()) return res.status(400).json({ success: false, message: 'Goal text required' });
  try {
    const mem = await pool.query('SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    if (mem.rows.length === 0) return res.status(403).json({ success: false, message: 'Not a member' });

    await pool.query(
      'INSERT INTO session_goals (group_id, created_by, goal_text) VALUES ($1,$2,$3)',
      [id, userId, goal_text.trim()]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Add goal error:', err);
    res.status(500).json({ success: false, message: 'Failed to add goal' });
  }
});

// ── 12. PATCH /api/study-groups/:id/goals/:goalId ───────────
app.patch('/api/study-groups/:id/goals/:goalId', authMiddleware, async (req, res) => {
  const { goalId } = req.params;
  const userId      = req.user.userId;
  const { completed } = req.body;
  try {
    await pool.query(
      `UPDATE session_goals SET
         completed    = $1,
         completed_by = $2,
         completed_at = $3
       WHERE id = $4`,
      [completed, completed ? userId : null, completed ? new Date() : null, goalId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Toggle goal error:', err);
    res.status(500).json({ success: false, message: 'Failed to update goal' });
  }
});

// ── 13. DELETE /api/study-groups/:id/goals/:goalId ──────────
app.delete('/api/study-groups/:id/goals/:goalId', authMiddleware, async (req, res) => {
  const { goalId } = req.params;
  const userId      = req.user.userId;
  try {
    await pool.query(
      'DELETE FROM session_goals WHERE id=$1 AND created_by=$2',
      [goalId, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Delete goal error:', err);
    res.status(500).json({ success: false, message: 'Failed to delete goal' });
  }
});

// ── 14. GET /api/study-groups/:id/session ───────────────────
app.get('/api/study-groups/:id/session', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    const activeCount = await pool.query(
      `SELECT COUNT(*)::int AS count FROM study_sessions WHERE group_id=$1 AND status='active'`,
      [id]
    );
    const userSess = await pool.query(
      `SELECT id FROM study_sessions WHERE group_id=$1 AND user_id=$2 AND status='active'`,
      [id, userId]
    );
    res.json({
      success: true,
      session: {
        active_count:      activeCount.rows[0].count,
        is_active_member:  userSess.rows.length > 0,
      },
    });
  } catch (err) {
    console.error('Get session error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch session' });
  }
});

// ── 15. POST /api/study-groups/:id/session/start ────────────
app.post('/api/study-groups/:id/session/start', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    const mem = await pool.query('SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2', [id, userId]);
    if (mem.rows.length === 0) return res.status(403).json({ success: false, message: 'Not a member' });

    await pool.query(
      `INSERT INTO study_sessions (group_id, user_id, status)
       VALUES ($1,$2,'active')
       ON CONFLICT (group_id, user_id, status) DO NOTHING`,
      [id, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Start session error:', err);
    res.status(500).json({ success: false, message: 'Failed to start session' });
  }
});

// ── 16. POST /api/study-groups/:id/session/end ──────────────
app.post('/api/study-groups/:id/session/end', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId  = req.user.userId;
  try {
    await pool.query(
      `UPDATE study_sessions SET status='ended', ended_at=NOW()
       WHERE group_id=$1 AND user_id=$2 AND status='active'`,
      [id, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('End session error:', err);
    res.status(500).json({ success: false, message: 'Failed to end session' });
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

// ── Bulk-import courses directly into timetables (used by PDF import) ─────────
// Bypasses the program_courses middle step entirely so there are no silent
// failures from missing tables or lookup mismatches.
app.post('/api/timetable/bulk', authMiddleware, async (req, res) => {
  const { courses } = req.body;
  if (!courses || !courses.length) {
    return res.status(400).json({ success: false, error: 'No courses provided' });
  }

  const inserted = [];
  const errors   = [];

  for (const course of courses) {
    try {
      const location = [course.building, course.room_number]
        .filter(Boolean).join(' ').trim() || course.location || '';

      const r = await pool.query(
        `INSERT INTO timetables
         (user_id, title, day_of_week, start_time, end_time,
          course_code, instructor, location, color)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *`,
        [
          req.user.userId,
          course.course_name || course.course_code || 'Untitled',
          Number(course.day_of_week),
          course.start_time,
          course.end_time,
          String(course.course_code || '').toUpperCase().trim(),
          course.instructor || '',
          location,
          '#3B82F6'
        ]
      );
      inserted.push(r.rows[0]);
    } catch (err) {
      console.error(`[timetable/bulk] Failed to insert ${course.course_code}:`, err.message);
      errors.push({ course_code: course.course_code, error: err.message });
    }
  }

  console.log(`[timetable/bulk] Inserted ${inserted.length}/${courses.length} courses for user ${req.user.userId}`);

  res.json({
    success: true,
    inserted: inserted.length,
    total: courses.length,
    entries: inserted,
    errors: errors.length ? errors : undefined
  });
});
// ─────────────────────────────────────────────────────────────────────────────

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

// ============================================
// PROGRAMS & COURSES
// ============================================

app.post('/api/programs', authMiddleware, async (req, res) => {
  const { programName, programCode, department, yearLevel, semester } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO programs (user_id, program_name, program_code, department, year_level, semester)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [req.user.userId, programName || '', programCode || '', department || '', yearLevel || null, semester || '']
    );
    res.json({ success: true, program: result.rows[0] });
  } catch (error) {
    console.error('Create program error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/programs', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, COUNT(pc.id) as course_count
       FROM programs p
       LEFT JOIN program_courses pc ON p.id = pc.program_id
       WHERE p.user_id = $1
       GROUP BY p.id
       ORDER BY p.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, programs: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

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

app.post('/api/program-courses/bulk', authMiddleware, async (req, res) => {
  const { programId, courses } = req.body;
  if (!courses || !courses.length) return res.status(400).json({ success: false, error: 'No courses provided' });
  try {
    for (const course of courses) {
      await pool.query(
        `INSERT INTO program_courses
         (program_id, course_code, course_name, day_of_week, start_time, end_time, location, building, room_number, instructor, year_level)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [programId, course.course_code, course.course_name || course.course_code,
         course.day_of_week, course.start_time, course.end_time,
         course.location || '', course.building || '', course.room_number || '',
         course.instructor || '', course.year_level || null]
      );
    }
    res.json({ success: true, imported: courses.length });
  } catch (error) {
    console.error('Bulk upload error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// ERROR HANDLING
// ============================================

// ============================================
// TIMETABLE IMPORT FROM PROGRAM
// ============================================

app.post('/api/timetable/import-from-program', authMiddleware, async (req, res) => {
  const { programId, selectedCourses } = req.body;
  
  try {
    // Track the program link (best effort — ignore if table doesn't exist yet)
    try {
      await pool.query(
        'INSERT INTO student_programs (user_id, program_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [req.user.userId, programId]
      );
    } catch (e) { /* non-fatal */ }
    
    // Read from program_courses (where bulk upload writes to)
    const result = await pool.query(
      `SELECT * FROM program_courses WHERE program_id = $1`,
      [programId]
    );

    if (!result.rows.length) {
      return res.json({ success: false, error: 'No courses found for this program. Make sure the PDF was parsed and courses were saved.' });
    }

    // Filter to selected courses if provided, otherwise import all
    // selectedCourses is an array of course_code strings
    const toImport = (selectedCourses && selectedCourses.length > 0)
      ? result.rows.filter(c => selectedCourses.includes(c.course_code))
      : result.rows;

    if (!toImport.length) {
      return res.json({ success: false, error: 'None of the selected course codes matched the stored courses.' });
    }

    // Insert each course into the user's timetable
    // Use ON CONFLICT DO NOTHING to avoid duplicates on re-import
    const importedRows = [];
    for (const course of toImport) {
      const location = [course.building, course.room_number].filter(Boolean).join(' ').trim() || course.location || '';
      try {
        const r = await pool.query(
          `INSERT INTO timetables 
           (user_id, title, day_of_week, start_time, end_time, course_code, instructor, location, color)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING *`,
          [req.user.userId,
           course.course_name || course.course_code,
           course.day_of_week,
           course.start_time,
           course.end_time,
           course.course_code,
           course.instructor || '',
           location,
           '#3B82F6']
        );
        importedRows.push(r.rows[0]);
      } catch (e) {
        console.error('Skipping course insert:', course.course_code, e.message);
      }
    }
    
    const imported = { length: importedRows.length };
    
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

// ============================================
// PDF PARSING — ImageMagick + Groq Vision (parallel)
// ============================================

async function pdfToImages(buffer) {
  const { spawnSync } = require('child_process');
  const fs = require('fs'), path = require('path'), os = require('os');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-'));
  const pdfPath = path.join(tmpDir, 'input.pdf');
  try {
    fs.writeFileSync(pdfPath, buffer);
    const result = spawnSync('convert', [
      '-density', '150', '-quality', '75',
      pdfPath,
      path.join(tmpDir, 'page-%d.jpg')
    ], { timeout: 60000 });
    if (result.status !== 0) {
      console.warn('[PDF] ImageMagick failed:', result.stderr?.toString() || result.error?.message);
      return [];
    }
    const files = fs.readdirSync(tmpDir)
      .filter(f => f.startsWith('page-') && f.endsWith('.jpg'))
      .sort((a, b) => parseInt(a.match(/page-(\d+)/)?.[1]??'0') - parseInt(b.match(/page-(\d+)/)?.[1]??'0'));
    const images = files.map(f => fs.readFileSync(path.join(tmpDir, f)).toString('base64'));
    console.log(`[PDF] ImageMagick converted ${images.length} pages`);
    return images;
  } catch (e) {
    console.warn('[PDF] ImageMagick error:', e.message);
    return [];
  } finally {
    try { spawnSync('rm', ['-rf', tmpDir]); } catch (_) {}
  }
}

const TIMETABLE_PROMPT = `Read a university timetable grid image.

STRUCTURE: The timetable is a grid where:
- ROWS = time slots (e.g. 7:00-7:55, 8:00-8:55, etc.)
- COLUMNS = departments/programs (e.g. ELECTRICAL, MECHANICAL, CIVIL, COMPUTER, etc.)
- Each cell contains: course code, course name, location/room, and instructor
- The DAY (Monday, Tuesday, etc.) is stated in the page heading — all entries on this page share that day

YOUR TASK: Read every cell in the grid. For each non-empty cell, output one JSON object.

Return ONLY a raw JSON array. No markdown, no backticks, no explanation — just the array starting with [ and ending with ].

Each object:
{
  "course_code": "EE 151",
  "course_name": "Electrical Circuits",
  "day_of_week": 1,
  "start_time": "08:00",
  "end_time": "08:55",
  "location": "VSLA",
  "instructor": "E. Twumasi",
  "program": "ELECTRICAL"
}

STRICT RULES:
1. day_of_week: 0=Sunday 1=Monday 2=Tuesday 3=Wednesday 4=Thursday 5=Friday 6=Saturday
2. Read the day from the page heading and use it for ALL entries on this page
3. start_time and end_time: 24-hour HH:MM format. Row label "7:00-7:55" → "07:00" and "07:55"
4. program: the COLUMN HEADER the course appears under — copy it exactly
5. course_code: the short code in the cell (e.g. "EE 151", "ME 201")
6. course_name: the longer name if shown, otherwise repeat the course_code
7. location: room or venue shown in the cell (e.g. "VSLA", "LH 2", "LAB 3")
8. instructor: lecturer name shown in the cell
9. If a field is not visible, use empty string ""
10. DO NOT skip any cell — scan every row, every column systematically
11. A course spanning multiple time rows = one entry with the full time range`;

app.post('/api/parse-timetable-pdf', authMiddleware, upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
    if (!GROQ_API_KEY) return res.status(503).json({ success: false, error: 'GROQ_API_KEY not set in Railway Variables.' });

    const images = await pdfToImages(req.file.buffer);
    if (!images.length) {
      return res.status(422).json({ success: false, error: 'Could not convert PDF to images. Check Dockerfile installs ImageMagick.' });
    }

    const timer = ms => new Promise((_, r) => setTimeout(() => r(new Error('TIMEOUT')), ms));

    // Process pages in batches of 3 to avoid Groq token rate limits
    const BATCH_SIZE = 3;
    const BATCH_DELAY_MS = 2000; // 2s pause between batches
    console.log(`[PDF] Processing ${images.length} pages in batches of ${BATCH_SIZE}...`);

    async function processPage(imageB64, i) {
      try {
        const groqRes = await Promise.race([
          fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_API_KEY}` },
            body: JSON.stringify({
              model: 'meta-llama/llama-4-scout-17b-16e-instruct',
              messages: [{
                role: 'user',
                content: [
                  { type: 'text', text: TIMETABLE_PROMPT },
                  { type: 'image_url', image_url: { url: `data:image/jpeg;base64,${imageB64}` } }
                ]
              }],
              temperature: 0.1,
              max_tokens: 4096,
            })
          }),
          timer(60000)
        ]);
        const data = await groqRes.json();
        if (!groqRes.ok) {
          // If rate limited, return empty and let other batches proceed
          console.warn(`[PDF] Groq error page ${i+1}:`, data.error?.message?.split('.')[0]);
          return [];
        }
        const text = data.choices?.[0]?.message?.content || '';
        const cleaned = text.replace(/```json\s*/gi, '').replace(/```\s*/gi, '');
        const jsonMatch = cleaned.match(/\[[\s\S]*\]/);
        if (!jsonMatch) { console.warn(`[PDF] No JSON from page ${i+1}`); return []; }
        const parsed = JSON.parse(jsonMatch[0]);
        console.log(`[PDF] Page ${i+1} -> ${Array.isArray(parsed) ? parsed.length : 0} courses`);
        return Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        console.warn(`[PDF] Page ${i+1} error:`, e.message);
        return [];
      }
    }

    const allResults = [];
    for (let b = 0; b < images.length; b += BATCH_SIZE) {
      const batch = images.slice(b, b + BATCH_SIZE);
      const batchNum = Math.floor(b / BATCH_SIZE) + 1;
      const totalBatches = Math.ceil(images.length / BATCH_SIZE);
      console.log(`[PDF] Batch ${batchNum}/${totalBatches} (pages ${b+1}-${Math.min(b+BATCH_SIZE, images.length)})...`);
      const batchResults = await Promise.all(batch.map((img, j) => processPage(img, b + j)));
      allResults.push(...batchResults);
      if (b + BATCH_SIZE < images.length) {
        await new Promise(r => setTimeout(r, BATCH_DELAY_MS));
      }
    }

    const allCourses = allResults.flat();

    if (!allCourses.length) {
      return res.status(422).json({ success: false, error: 'Groq could not extract any courses from this PDF.' });
    }

    // Normalize time to HH:MM 24-hour format
    const normalizeTime = (t) => {
      if (!t) return null;
      t = String(t).trim();
      // Already HH:MM
      if (/^\d{2}:\d{2}$/.test(t)) return t;
      // H:MM → 0-pad
      if (/^\d{1}:\d{2}$/.test(t)) return '0' + t;
      // Handle HH:MM:SS
      if (/^\d{2}:\d{2}:\d{2}$/.test(t)) return t.slice(0,5);
      // Handle 12-hour like "7:00 AM", "1:00 PM"
      const ampm = t.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
      if (ampm) {
        let h = parseInt(ampm[1]);
        const m = ampm[2];
        const period = ampm[3].toUpperCase();
        if (period === 'PM' && h < 12) h += 12;
        if (period === 'AM' && h === 12) h = 0;
        return String(h).padStart(2,'0') + ':' + m;
      }
      return t;
    };

    const seen = new Set();
    const courses = allCourses
      .filter(c => {
        // Skip entries with no course code or clearly garbage data
        if (!c.course_code || String(c.course_code).trim().length < 2) return false;
        if (c.day_of_week === undefined || c.day_of_week === null) return false;
        const key = `${c.course_code}|${c.day_of_week}|${c.start_time}|${c.program}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .map((c, i) => {
        const st = normalizeTime(c.start_time);
        const et = normalizeTime(c.end_time);
        return {
          id: `parsed-${Date.now()}-${i}`,
          course_code: String(c.course_code || '').toUpperCase().trim(),
          course_name: String(c.course_name || c.course_code || '').trim(),
          program: String(c.program || '').trim(),
          year: 'Not specified',
          day_of_week: Number(c.day_of_week),
          start_time: st || '08:00',
          end_time: et || '09:00',
          location: String(c.location || '').trim(),
          instructor: String(c.instructor || '').trim(),
          checked: true,
        };
      })
      .filter(c => c.start_time && c.end_time);

    console.log(`[PDF] Done — ${courses.length} unique courses from ${images.length} pages`);
    return res.json({ success: true, courses });

  } catch (error) {
    console.error('[PDF] Error:', error.message);
    res.status(500).json({
      success: false,
      error: error.message === 'TIMEOUT' ? 'Groq timed out. Try again.' : 'Failed: ' + error.message
    });
  }
});



// ============================================================================
// STUDENTHUB — BACKEND ADDITIONS v2
// Drop this entire block into server.js JUST BEFORE the 404 handler.
// Also run POST /api/migrate-v2 once after deploy to apply the schema changes.
// ============================================================================

// ── Missing path import (required by uploadToSupabase) ───────────────────────
const path = require('path');

// ============================================================================
// MIGRATION — Run POST /api/migrate-v2 once to add all new tables + columns
// ============================================================================

const migrationSQL = `
-- Extend users table with XP / gamification fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS xp_points        INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS level            VARCHAR(20) DEFAULT 'Bronze';
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_streak     INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_date  DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS programme        VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS year_of_study    VARCHAR(10);
ALTER TABLE users ADD COLUMN IF NOT EXISTS subjects         TEXT[] DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS study_style      VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS study_times      TEXT[] DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS goals            TEXT[] DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarded_at     TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reputation_score INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS rank_percentile  DECIMAL(5,2) DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS store_views      INTEGER DEFAULT 0;

-- Extend library_resources with extra columns used in routes
ALTER TABLE library_resources ADD COLUMN IF NOT EXISTS category      VARCHAR(100) DEFAULT 'Lecture Notes';
ALTER TABLE library_resources ADD COLUMN IF NOT EXISTS thumbnail_url TEXT;

-- Extend study_groups with fields used in routes
ALTER TABLE study_groups ADD COLUMN IF NOT EXISTS program     VARCHAR(100);
ALTER TABLE study_groups ADD COLUMN IF NOT EXISTS study_mode  VARCHAR(50) DEFAULT 'social';
ALTER TABLE study_groups ADD COLUMN IF NOT EXISTS year_filter VARCHAR(10);

-- Extend notifications with sent tracking
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS sent     BOOLEAN DEFAULT false;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS sent_at  TIMESTAMP;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS read_at  TIMESTAMP;

-- Extend assignments with submitted_at
ALTER TABLE assignments ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMP;

-- Extend timetables with notification_minutes_before
ALTER TABLE timetables ADD COLUMN IF NOT EXISTS notification_minutes_before INTEGER DEFAULT 30;

-- Study sessions (for study groups)
CREATE TABLE IF NOT EXISTS study_sessions (
  id          SERIAL PRIMARY KEY,
  group_id    INTEGER REFERENCES study_groups(id) ON DELETE CASCADE,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  status      VARCHAR(20) DEFAULT 'active',
  started_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ended_at    TIMESTAMP,
  UNIQUE(group_id, user_id, status)
);

-- Session goals (for study groups)
CREATE TABLE IF NOT EXISTS session_goals (
  id           SERIAL PRIMARY KEY,
  group_id     INTEGER REFERENCES study_groups(id) ON DELETE CASCADE,
  created_by   INTEGER REFERENCES users(id) ON DELETE CASCADE,
  goal_text    TEXT NOT NULL,
  goal_date    DATE DEFAULT CURRENT_DATE,
  completed    BOOLEAN DEFAULT false,
  completed_by INTEGER REFERENCES users(id),
  completed_at TIMESTAMP,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Library comments
CREATE TABLE IF NOT EXISTS library_comments (
  id          SERIAL PRIMARY KEY,
  resource_id INTEGER REFERENCES library_resources(id) ON DELETE CASCADE,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  content     TEXT NOT NULL,
  parent_id   INTEGER REFERENCES library_comments(id) ON DELETE CASCADE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Library comment likes
CREATE TABLE IF NOT EXISTS library_comment_likes (
  id         SERIAL PRIMARY KEY,
  comment_id INTEGER REFERENCES library_comments(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(comment_id, user_id)
);

-- Stores table
CREATE TABLE IF NOT EXISTS stores (
  id           SERIAL PRIMARY KEY,
  user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
  owner_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  store_name   VARCHAR(255),
  slug         VARCHAR(100) UNIQUE,
  description  TEXT,
  banner_url   TEXT,
  category     VARCHAR(100),
  location     VARCHAR(255),
  phone        VARCHAR(50),
  email        VARCHAR(255),
  website      TEXT,
  rating       DECIMAL(3,2) DEFAULT 0,
  status       VARCHAR(20) DEFAULT 'active',
  store_views  INTEGER DEFAULT 0,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Store followers
CREATE TABLE IF NOT EXISTS store_followers (
  id         SERIAL PRIMARY KEY,
  store_id   INTEGER REFERENCES stores(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(store_id, user_id)
);

-- Seller followers (direct user follows for sellers)
CREATE TABLE IF NOT EXISTS seller_followers (
  id          SERIAL PRIMARY KEY,
  seller_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
  follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(seller_id, follower_id)
);

-- Store reviews
CREATE TABLE IF NOT EXISTS store_reviews (
  id          SERIAL PRIMARY KEY,
  store_id    INTEGER REFERENCES stores(id) ON DELETE CASCADE,
  reviewer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  rating      INTEGER CHECK (rating >= 1 AND rating <= 5),
  review_text TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(store_id, reviewer_id)
);

-- Classroom locations
CREATE TABLE IF NOT EXISTS classroom_locations (
  id            SERIAL PRIMARY KEY,
  user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
  building      VARCHAR(100),
  room_number   VARCHAR(50),
  location_name VARCHAR(255),
  location_lat  DECIMAL(10,8),
  location_lng  DECIMAL(11,8),
  notes         TEXT,
  is_public     BOOLEAN DEFAULT false,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, building, room_number)
);

-- ── NEW REWARD SYSTEM TABLES ──────────────────────────────────────────────

-- Badges catalogue
CREATE TABLE IF NOT EXISTS badges (
  id          SERIAL PRIMARY KEY,
  slug        VARCHAR(60) UNIQUE NOT NULL,
  name        VARCHAR(100) NOT NULL,
  description TEXT,
  icon        VARCHAR(10),
  tier        VARCHAR(20) DEFAULT 'bronze',
  xp_reward   INTEGER DEFAULT 0,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Badges earned by users
CREATE TABLE IF NOT EXISTS user_badges (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  badge_id   INTEGER REFERENCES badges(id) ON DELETE CASCADE,
  earned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, badge_id)
);

-- XP transaction ledger
CREATE TABLE IF NOT EXISTS point_transactions (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  action      VARCHAR(60) NOT NULL,
  points      INTEGER NOT NULL,
  reference   TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User follows (who follows whom)
CREATE TABLE IF NOT EXISTS user_follows (
  id          SERIAL PRIMARY KEY,
  follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(follower_id, following_id)
);

-- Direct messages
CREATE TABLE IF NOT EXISTS direct_messages (
  id          SERIAL PRIMARY KEY,
  sender_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  content     TEXT NOT NULL,
  is_read     BOOLEAN DEFAULT false,
  read_at     TIMESTAMP,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Event RSVPs
CREATE TABLE IF NOT EXISTS event_rsvps (
  id         SERIAL PRIMARY KEY,
  event_id   INTEGER REFERENCES school_events(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  status     VARCHAR(20) DEFAULT 'going',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(event_id, user_id)
);

-- Bounty fulfillments
CREATE TABLE IF NOT EXISTS bounty_fulfillments (
  id           SERIAL PRIMARY KEY,
  bounty_id    INTEGER REFERENCES library_bounties(id) ON DELETE CASCADE,
  fulfiller_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  resource_id  INTEGER REFERENCES library_resources(id) ON DELETE CASCADE,
  note         TEXT,
  accepted     BOOLEAN DEFAULT false,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Marketplace service images
ALTER TABLE marketplace_services ADD COLUMN IF NOT EXISTS images TEXT[] DEFAULT '{}';

-- Indexes for new tables
CREATE INDEX IF NOT EXISTS idx_point_tx_user    ON point_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_badges_user ON user_badges(user_id);
CREATE INDEX IF NOT EXISTS idx_dm_sender        ON direct_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_dm_receiver      ON direct_messages(receiver_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_fr  ON user_follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_fg  ON user_follows(following_id);
CREATE INDEX IF NOT EXISTS idx_event_rsvps      ON event_rsvps(event_id);
CREATE INDEX IF NOT EXISTS idx_session_goals    ON session_goals(group_id);
CREATE INDEX IF NOT EXISTS idx_study_sessions   ON study_sessions(group_id);
CREATE INDEX IF NOT EXISTS idx_library_comments ON library_comments(resource_id);

CREATE TABLE IF NOT EXISTS campus_pulse_posts (
  id           SERIAL PRIMARY KEY,
  user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
  category     VARCHAR(40) NOT NULL DEFAULT 'general',
  text         TEXT NOT NULL,
  is_anonymous BOOLEAN DEFAULT TRUE,
  author_name  VARCHAR(100) DEFAULT 'Anonymous',
  is_pinned    BOOLEAN DEFAULT FALSE,
  likes        INTEGER DEFAULT 0,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS campus_pulse_reactions (
  id      SERIAL PRIMARY KEY,
  post_id INTEGER REFERENCES campus_pulse_posts(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  emoji   VARCHAR(10) NOT NULL,
  UNIQUE(post_id, user_id, emoji)
);
CREATE TABLE IF NOT EXISTS campus_pulse_comments (
  id         SERIAL PRIMARY KEY,
  post_id    INTEGER REFERENCES campus_pulse_posts(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  text       TEXT NOT NULL,
  author_name VARCHAR(100) DEFAULT 'Anonymous',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS grade_subjects (
  id           SERIAL PRIMARY KEY,
  user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
  name         VARCHAR(120) NOT NULL,
  code         VARCHAR(30),
  credits      DECIMAL(4,1) DEFAULT 3,
  total_weight DECIMAL(6,2) DEFAULT 100,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS grade_entries (
  id         SERIAL PRIMARY KEY,
  subject_id INTEGER REFERENCES grade_subjects(id) ON DELETE CASCADE,
  name       VARCHAR(120) NOT NULL,
  pct        DECIMAL(5,2) NOT NULL,
  weight     DECIMAL(5,2) DEFAULT 1,
  logged_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pulse_posts ON campus_pulse_posts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_grade_subjects ON grade_subjects(user_id);
CREATE INDEX IF NOT EXISTS idx_grade_entries ON grade_entries(subject_id)
`;

app.post('/api/migrate-v2', async (req, res) => {
  try {
    const statements = migrationSQL
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);

    const results = [];
    for (const sql of statements) {
      try {
        await pool.query(sql);
        results.push({ ok: true, sql: sql.slice(0, 60) });
      } catch (err) {
        results.push({ ok: false, sql: sql.slice(0, 60), err: err.message });
      }
    }

    await seedBadges();
    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// REWARD SYSTEM — XP ACTIONS, LEVELS, HELPERS
// ============================================================================

const XP_ACTIONS = {
  resource_upload:      20,
  upvote_received:       5,
  homework_answered:    15,
  study_task_completed: 10,
  assignment_submitted:  5,
  daily_login:          10,
  class_joined:          3,
  study_group_created:  15,
  study_group_joined:    5,
  item_listed:          10,
  review_given:          5,
  library_upvote_given:  2,
  bounty_fulfilled:     30,
  login_streak_7:       50,
  login_streak_30:     200,
};

function calcLevel(xp) {
  if (xp >= 2000) return 'Diamond';
  if (xp >= 800)  return 'Platinum';
  if (xp >= 400)  return 'Gold';
  if (xp >= 150)  return 'Silver';
  return 'Bronze';
}

// Non-blocking — never delays a response
async function awardXP(userId, action, reference = null) {
  const points = XP_ACTIONS[action];
  if (!points) return;
  try {
    await pool.query(
      `INSERT INTO point_transactions (user_id, action, points, reference)
       VALUES ($1, $2, $3, $4)`,
      [userId, action, points, reference]
    );
    const result = await pool.query(
      `UPDATE users
       SET xp_points = xp_points + $1,
           level     = $2,
           updated_at = NOW()
       WHERE id = $3
       RETURNING xp_points`,
      [points, calcLevel((await pool.query('SELECT xp_points FROM users WHERE id=$1', [userId])).rows[0]?.xp_points + points || points), userId]
    );
    const newXp = result.rows[0]?.xp_points || 0;
    // Update level correctly after increment
    await pool.query(
      'UPDATE users SET level = $1 WHERE id = $2',
      [calcLevel(newXp), userId]
    );
    await checkBadges(userId);
  } catch (err) {
    console.error('[XP] award error:', err.message);
  }
}

async function checkBadges(userId) {
  try {
    const [uploads, answers, groups, reviews, streak, xp] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM library_resources WHERE uploader_id=$1', [userId]),
      pool.query('SELECT COUNT(*) FROM homework_responses WHERE responder_id=$1', [userId]),
      pool.query('SELECT COUNT(*) FROM study_group_members WHERE user_id=$1', [userId]),
      pool.query('SELECT COUNT(*) FROM reviews WHERE reviewer_id=$1', [userId]),
      pool.query('SELECT login_streak FROM users WHERE id=$1', [userId]),
      pool.query('SELECT xp_points FROM users WHERE id=$1', [userId]),
    ]);

    const u  = parseInt(uploads.rows[0].count);
    const a  = parseInt(answers.rows[0].count);
    const g  = parseInt(groups.rows[0].count);
    const rv = parseInt(reviews.rows[0].count);
    const ls = parseInt(streak.rows[0]?.login_streak || 0);
    const xpv = parseInt(xp.rows[0]?.xp_points || 0);

    const toAward = [];
    if (u >= 1)   toAward.push('first_upload');
    if (u >= 5)   toAward.push('bookworm');
    if (u >= 20)  toAward.push('scholar');
    if (a >= 1)   toAward.push('first_helper');
    if (a >= 10)  toAward.push('mentor');
    if (a >= 50)  toAward.push('sage');
    if (g >= 1)   toAward.push('study_buddy');
    if (g >= 5)   toAward.push('team_player');
    if (g >= 10)  toAward.push('social_butterfly');
    if (rv >= 1)  toAward.push('reviewer');
    if (ls >= 7)  toAward.push('streak_7');
    if (ls >= 30) toAward.push('streak_30');
    if (xpv >= 500)  toAward.push('rising_star');
    if (xpv >= 2000) toAward.push('legend');

    for (const slug of toAward) {
      const badge = await pool.query('SELECT id FROM badges WHERE slug=$1', [slug]);
      if (!badge.rows.length) continue;
      const badgeId = badge.rows[0].id;
      const already = await pool.query(
        'SELECT id FROM user_badges WHERE user_id=$1 AND badge_id=$2',
        [userId, badgeId]
      );
      if (!already.rows.length) {
        await pool.query(
          'INSERT INTO user_badges (user_id, badge_id) VALUES ($1,$2)',
          [userId, badgeId]
        );
        // Notify
        await pool.query(
          `INSERT INTO notifications (user_id, notification_type, title, message, scheduled_time)
           VALUES ($1, 'badge', $2, $3, NOW())`,
          [userId, `Badge Unlocked!`,
           `You earned the "${slug.replace(/_/g,' ')}" badge. Keep it up.`]
        );
      }
    }
  } catch (err) {
    console.error('[Badge] check error:', err.message);
  }
}

async function seedBadges() {
  const badges = [
    { slug: 'first_upload',      name: 'First Upload',        icon: '📄', tier: 'bronze',   xp: 10,  desc: 'Uploaded your first resource.' },
    { slug: 'bookworm',          name: 'Bookworm',             icon: '📚', tier: 'silver',   xp: 25,  desc: 'Uploaded 5 resources.' },
    { slug: 'scholar',           name: 'Scholar',              icon: '🎓', tier: 'gold',     xp: 75,  desc: 'Uploaded 20 resources.' },
    { slug: 'first_helper',      name: 'First Helper',         icon: '🙋', tier: 'bronze',   xp: 15,  desc: 'Answered a homework question.' },
    { slug: 'mentor',            name: 'Mentor',               icon: '🧑‍🏫', tier: 'silver', xp: 40,  desc: 'Answered 10 homework questions.' },
    { slug: 'sage',              name: 'Sage',                 icon: '🦉', tier: 'platinum', xp: 150, desc: 'Answered 50 homework questions.' },
    { slug: 'study_buddy',       name: 'Study Buddy',          icon: '🤝', tier: 'bronze',   xp: 10,  desc: 'Joined your first study group.' },
    { slug: 'team_player',       name: 'Team Player',          icon: '🏆', tier: 'silver',   xp: 30,  desc: 'Joined 5 study groups.' },
    { slug: 'social_butterfly',  name: 'Social Butterfly',     icon: '🦋', tier: 'gold',     xp: 75,  desc: 'Active in 10+ study groups.' },
    { slug: 'marketplace_debut', name: 'Marketplace Debut',    icon: '🛍️', tier: 'bronze',   xp: 15,  desc: 'Listed your first item.' },
    { slug: 'top_seller',        name: 'Top Seller',           icon: '💎', tier: 'gold',     xp: 100, desc: 'Listed 20+ items.' },
    { slug: 'streak_7',          name: '7-Day Streak',         icon: '🔥', tier: 'silver',   xp: 50,  desc: 'Logged in 7 days in a row.' },
    { slug: 'streak_30',         name: 'Monthly Grind',        icon: '⚡', tier: 'platinum', xp: 200, desc: 'Logged in 30 days in a row.' },
    { slug: 'reviewer',          name: 'Reviewer',             icon: '⭐', tier: 'bronze',   xp: 10,  desc: 'Left your first review.' },
    { slug: 'rising_star',       name: 'Rising Star',          icon: '🌟', tier: 'gold',     xp: 50,  desc: 'Reached 500 XP.' },
    { slug: 'legend',            name: 'Legend',               icon: '👑', tier: 'diamond',  xp: 300, desc: 'Reached 2000 XP.' },
  ];

  for (const b of badges) {
    await pool.query(
      `INSERT INTO badges (slug, name, description, icon, tier, xp_reward)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (slug) DO UPDATE
         SET name=$2, description=$3, icon=$4, tier=$5, xp_reward=$6`,
      [b.slug, b.name, b.desc, b.icon, b.tier, b.xp]
    );
  }
}

// ============================================================================
// REWARDS ROUTES
// ============================================================================

// GET /api/rewards/me — own XP summary
app.get('/api/rewards/me', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.userId;
    const user = await pool.query(
      `SELECT id, full_name, xp_points, level, login_streak, reputation_score, rank_percentile
       FROM users WHERE id=$1`,
      [uid]
    );
    if (!user.rows.length) return res.status(404).json({ success: false, message: 'Not found' });

    const badges = await pool.query(
      `SELECT b.slug, b.name, b.icon, b.tier, b.description, ub.earned_at
       FROM user_badges ub
       JOIN badges b ON b.id = ub.badge_id
       WHERE ub.user_id=$1
       ORDER BY ub.earned_at DESC`,
      [uid]
    );

    const history = await pool.query(
      `SELECT action, points, reference, created_at
       FROM point_transactions
       WHERE user_id=$1
       ORDER BY created_at DESC
       LIMIT 30`,
      [uid]
    );

    const rank = await pool.query(
      `SELECT COUNT(*)+1 AS rank FROM users WHERE xp_points > (SELECT xp_points FROM users WHERE id=$1)`,
      [uid]
    );

    res.json({
      success: true,
      rewards: {
        ...user.rows[0],
        badges: badges.rows,
        recentHistory: history.rows,
        globalRank: parseInt(rank.rows[0].rank),
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/rewards/leaderboard?institution=&limit=20
app.get('/api/rewards/leaderboard', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const institution = req.query.institution;

    const params = institution ? [institution, limit] : [limit];
    const where  = institution ? 'WHERE institution=$1' : '';
    const lParam = institution ? '$2' : '$1';

    const result = await pool.query(
      `SELECT id, full_name, institution, profile_image_url, xp_points, level, login_streak,
              ROW_NUMBER() OVER (ORDER BY xp_points DESC) AS rank
       FROM users
       ${where}
       ORDER BY xp_points DESC
       LIMIT ${lParam}`,
      params
    );

    // Highlight current user's position
    const myRank = await pool.query(
      `SELECT COUNT(*)+1 AS rank FROM users WHERE xp_points > (SELECT xp_points FROM users WHERE id=$1)`,
      [req.user.userId]
    );

    res.json({
      success: true,
      leaderboard: result.rows,
      myRank: parseInt(myRank.rows[0].rank),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/rewards/badges — all badges + which ones you have
app.get('/api/rewards/badges', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*,
              CASE WHEN ub.id IS NOT NULL THEN true ELSE false END AS earned,
              ub.earned_at
       FROM badges b
       LEFT JOIN user_badges ub ON ub.badge_id = b.id AND ub.user_id=$1
       ORDER BY b.tier DESC, b.xp_reward DESC`,
      [req.user.userId]
    );
    res.json({ success: true, badges: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/rewards/history?limit=50
app.get('/api/rewards/history', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const result = await pool.query(
      `SELECT action, points, reference, created_at
       FROM point_transactions
       WHERE user_id=$1
       ORDER BY created_at DESC
       LIMIT $2`,
      [req.user.userId, limit]
    );
    res.json({ success: true, history: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// DASHBOARD STATS
// ============================================================================

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.userId;
    const [user, uploads, groups, assignments, exams, unread, upcoming] = await Promise.all([
      pool.query(
        `SELECT xp_points, level, login_streak, reputation_score FROM users WHERE id=$1`,
        [uid]
      ),
      pool.query('SELECT COUNT(*) FROM library_resources WHERE uploader_id=$1', [uid]),
      pool.query('SELECT COUNT(*) FROM study_group_members WHERE user_id=$1', [uid]),
      pool.query(
        `SELECT COUNT(*) FROM assignments WHERE user_id=$1 AND status='pending' AND due_date > NOW()`,
        [uid]
      ),
      pool.query(
        `SELECT COUNT(*) FROM exam_schedules WHERE user_id=$1 AND exam_date > NOW()`,
        [uid]
      ),
      pool.query(
        `SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read=false AND scheduled_time<=NOW()`,
        [uid]
      ),
      pool.query(
        `SELECT title, due_date FROM assignments
         WHERE user_id=$1 AND status='pending' AND due_date > NOW()
         ORDER BY due_date ASC LIMIT 5`,
        [uid]
      ),
    ]);

    const rank = await pool.query(
      `SELECT COUNT(*)+1 AS rank FROM users WHERE xp_points > (SELECT xp_points FROM users WHERE id=$1)`,
      [uid]
    );

    res.json({
      success: true,
      stats: {
        xp:              parseInt(user.rows[0]?.xp_points || 0),
        level:           user.rows[0]?.level || 'Bronze',
        loginStreak:     parseInt(user.rows[0]?.login_streak || 0),
        reputation:      parseInt(user.rows[0]?.reputation_score || 0),
        globalRank:      parseInt(rank.rows[0].rank),
        uploads:         parseInt(uploads.rows[0].count),
        studyGroups:     parseInt(groups.rows[0].count),
        pendingAssignments: parseInt(assignments.rows[0].count),
        upcomingExams:   parseInt(exams.rows[0].count),
        unreadNotifications: parseInt(unread.rows[0].count),
        upcomingDeadlines: upcoming.rows,
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// USER SEARCH + PROFILES + FOLLOWS
// ============================================================================

// GET /api/users/search?q=&institution=
app.get('/api/users/search', authMiddleware, async (req, res) => {
  const { q, institution } = req.query;
  if (!q || q.length < 2) {
    return res.status(400).json({ success: false, message: 'Search query too short' });
  }
  try {
    const term = `%${q}%`;
    const params = institution
      ? [term, term, term, institution, req.user.userId]
      : [term, term, term, req.user.userId];
    const institutionClause = institution ? 'AND u.institution=$4' : '';
    const uidParam = institution ? '$5' : '$4';

    const result = await pool.query(
      `SELECT u.id, u.full_name, u.student_id, u.institution, u.profile_image_url,
              u.xp_points, u.level, u.bio,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=${uidParam} AND following_id=u.id) AS is_following
       FROM users u
       WHERE (u.full_name ILIKE $1 OR u.student_id ILIKE $2 OR u.institution ILIKE $3)
       ${institutionClause}
       AND u.id != ${uidParam}
       ORDER BY u.xp_points DESC
       LIMIT 30`,
      params
    );
    res.json({ success: true, users: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/users/:id/profile — public profile
app.get('/api/users/:id/profile', authMiddleware, async (req, res) => {
  const { id } = req.params;
  if (isNaN(id)) return res.status(400).json({ success: false, message: 'Invalid ID' });
  try {
    const user = await pool.query(
      `SELECT u.id, u.full_name, u.institution, u.profile_image_url, u.bio,
              u.xp_points, u.level, u.login_streak, u.reputation_score,
              u.created_at,
              (SELECT COUNT(*) FROM library_resources WHERE uploader_id=u.id) AS uploads,
              (SELECT COUNT(*) FROM study_group_members WHERE user_id=u.id) AS groups_joined,
              (SELECT COUNT(*) FROM user_follows WHERE following_id=u.id) AS followers,
              (SELECT COUNT(*) FROM user_follows WHERE follower_id=u.id) AS following,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$2 AND following_id=u.id) AS is_following
       FROM users u WHERE u.id=$1`,
      [id, req.user.userId]
    );
    if (!user.rows.length) return res.status(404).json({ success: false, message: 'User not found' });

    const badges = await pool.query(
      `SELECT b.slug, b.name, b.icon, b.tier FROM user_badges ub
       JOIN badges b ON b.id=ub.badge_id WHERE ub.user_id=$1 ORDER BY ub.earned_at DESC LIMIT 6`,
      [id]
    );

    const recentUploads = await pool.query(
      `SELECT id, title, subject, created_at FROM library_resources
       WHERE uploader_id=$1 AND is_public=true ORDER BY created_at DESC LIMIT 5`,
      [id]
    );

    res.json({
      success: true,
      profile: user.rows[0],
      badges: badges.rows,
      recentUploads: recentUploads.rows,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/users/:id/follow — toggle follow
app.post('/api/users/:id/follow', authMiddleware, async (req, res) => {
  const targetId = parseInt(req.params.id);
  const uid = req.user.userId;
  if (isNaN(targetId)) return res.status(400).json({ success: false, message: 'Invalid ID' });
  if (targetId === uid) return res.status(400).json({ success: false, message: 'Cannot follow yourself' });
  try {
    const existing = await pool.query(
      'SELECT id FROM user_follows WHERE follower_id=$1 AND following_id=$2',
      [uid, targetId]
    );
    if (existing.rows.length) {
      await pool.query('DELETE FROM user_follows WHERE follower_id=$1 AND following_id=$2', [uid, targetId]);
      return res.json({ success: true, following: false });
    }
    await pool.query(
      'INSERT INTO user_follows (follower_id, following_id) VALUES ($1,$2)',
      [uid, targetId]
    );
    res.json({ success: true, following: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/users/me/followers
app.get('/api/users/me/followers', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.full_name, u.profile_image_url, u.institution, u.level, uf.created_at
       FROM user_follows uf
       JOIN users u ON u.id = uf.follower_id
       WHERE uf.following_id=$1
       ORDER BY uf.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, followers: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/users/me/following
app.get('/api/users/me/following', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.full_name, u.profile_image_url, u.institution, u.level, uf.created_at
       FROM user_follows uf
       JOIN users u ON u.id = uf.following_id
       WHERE uf.follower_id=$1
       ORDER BY uf.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, following: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// DIRECT MESSAGES
// ============================================================================

// GET /api/messages/inbox — list of conversations
app.get('/api/messages/inbox', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.userId;
    const result = await pool.query(
      `SELECT DISTINCT ON (other_id)
         other_id,
         other_name,
         other_image,
         content AS last_message,
         created_at AS last_at,
         unread_count
       FROM (
         SELECT
           CASE WHEN dm.sender_id=$1 THEN dm.receiver_id ELSE dm.sender_id END AS other_id,
           CASE WHEN dm.sender_id=$1 THEN ru.full_name    ELSE su.full_name   END AS other_name,
           CASE WHEN dm.sender_id=$1 THEN ru.profile_image_url ELSE su.profile_image_url END AS other_image,
           dm.content,
           dm.created_at,
           (SELECT COUNT(*) FROM direct_messages
            WHERE sender_id=(CASE WHEN dm.sender_id=$1 THEN dm.receiver_id ELSE dm.sender_id END)
              AND receiver_id=$1 AND is_read=false) AS unread_count
         FROM direct_messages dm
         JOIN users su ON su.id = dm.sender_id
         JOIN users ru ON ru.id = dm.receiver_id
         WHERE dm.sender_id=$1 OR dm.receiver_id=$1
         ORDER BY dm.created_at DESC
       ) t
       ORDER BY other_id, last_at DESC`,
      [uid]
    );
    res.json({ success: true, conversations: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/messages/:userId — thread with a specific user
app.get('/api/messages/:userId', authMiddleware, async (req, res) => {
  const other = parseInt(req.params.userId);
  const uid = req.user.userId;
  if (isNaN(other)) return res.status(400).json({ success: false, message: 'Invalid user ID' });
  try {
    // Mark received messages as read
    await pool.query(
      `UPDATE direct_messages SET is_read=true, read_at=NOW()
       WHERE sender_id=$1 AND receiver_id=$2 AND is_read=false`,
      [other, uid]
    );
    const messages = await pool.query(
      `SELECT dm.*, u.full_name AS sender_name, u.profile_image_url AS sender_image
       FROM direct_messages dm
       JOIN users u ON u.id = dm.sender_id
       WHERE (dm.sender_id=$1 AND dm.receiver_id=$2)
          OR (dm.sender_id=$2 AND dm.receiver_id=$1)
       ORDER BY dm.created_at ASC
       LIMIT 200`,
      [uid, other]
    );
    // Get other user's info
    const otherUser = await pool.query(
      'SELECT id, full_name, profile_image_url, institution FROM users WHERE id=$1',
      [other]
    );
    res.json({ success: true, messages: messages.rows, user: otherUser.rows[0] || null });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/messages — send a DM
app.post('/api/messages', authMiddleware, async (req, res) => {
  const { receiverId, content } = req.body;
  const uid = req.user.userId;
  if (!receiverId || !content?.trim()) {
    return res.status(400).json({ success: false, message: 'Receiver and content required' });
  }
  if (parseInt(receiverId) === uid) {
    return res.status(400).json({ success: false, message: 'Cannot message yourself' });
  }
  try {
    const receiver = await pool.query('SELECT id FROM users WHERE id=$1', [receiverId]);
    if (!receiver.rows.length) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const result = await pool.query(
      `INSERT INTO direct_messages (sender_id, receiver_id, content)
       VALUES ($1,$2,$3) RETURNING *`,
      [uid, receiverId, content.trim()]
    );
    // Deliver a notification to receiver
    await pool.query(
      `INSERT INTO notifications (user_id, notification_type, reference_id, title, message, scheduled_time)
       VALUES ($1,'message',$2,$3,$4,NOW())`,
      [receiverId, uid, 'New Message',
       (await pool.query('SELECT full_name FROM users WHERE id=$1',[uid])).rows[0]?.full_name + ' sent you a message']
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/messages/:id — delete own message
app.delete('/api/messages/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM direct_messages WHERE id=$1 AND sender_id=$2 RETURNING id',
      [req.params.id, req.user.userId]
    );
    if (!result.rowCount) return res.status(403).json({ success: false, message: 'Not found or unauthorized' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// LIBRARY BOUNTIES (FULL IMPLEMENTATION)
// ============================================================================

// GET /api/library/bounties
app.get('/api/library/bounties', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lb.*, u.full_name AS requester_name, u.profile_image_url AS requester_image,
              (SELECT COUNT(*) FROM bounty_fulfillments WHERE bounty_id=lb.id) AS fulfillment_count
       FROM library_bounties lb
       JOIN users u ON u.id = lb.requester_id
       WHERE lb.status='open'
       ORDER BY lb.reward_points DESC, lb.created_at DESC`,
    );
    res.json({ success: true, bounties: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/library/bounties — create a bounty request
app.post('/api/library/bounties', authMiddleware, async (req, res) => {
  const { courseCode, description, rewardPoints } = req.body;
  if (!courseCode) return res.status(400).json({ success: false, message: 'Course code required' });
  try {
    const result = await pool.query(
      `INSERT INTO library_bounties (requester_id, course_code, description, reward_points)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [req.user.userId, courseCode.toUpperCase().trim(), description || '', rewardPoints || 0]
    );
    res.json({ success: true, bounty: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/library/bounties/:id/fulfill — fulfill a bounty
app.post('/api/library/bounties/:id/fulfill', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  const bountyId = parseInt(req.params.id);
  const { resourceId, note } = req.body;
  if (!resourceId) return res.status(400).json({ success: false, message: 'Resource ID required' });
  try {
    const bounty = await pool.query('SELECT * FROM library_bounties WHERE id=$1', [bountyId]);
    if (!bounty.rows.length) return res.status(404).json({ success: false, message: 'Bounty not found' });
    if (bounty.rows[0].status !== 'open') {
      return res.status(400).json({ success: false, message: 'Bounty is already closed' });
    }
    if (bounty.rows[0].requester_id === uid) {
      return res.status(400).json({ success: false, message: 'Cannot fulfill your own bounty' });
    }
    // Check resource belongs to fulfiller
    const res2 = await pool.query(
      'SELECT id FROM library_resources WHERE id=$1 AND uploader_id=$2',
      [resourceId, uid]
    );
    if (!res2.rows.length) {
      return res.status(403).json({ success: false, message: 'You must own the resource to fulfill a bounty' });
    }
    // Insert fulfillment
    const fulfillment = await pool.query(
      `INSERT INTO bounty_fulfillments (bounty_id, fulfiller_id, resource_id, note)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [bountyId, uid, resourceId, note || '']
    );
    // Close the bounty
    await pool.query('UPDATE library_bounties SET status=$1 WHERE id=$2', ['fulfilled', bountyId]);
    // Award XP for bounty fulfillment
    setImmediate(() => awardXP(uid, 'bounty_fulfilled', `bounty:${bountyId}`));
    // Notify requester
    await pool.query(
      `INSERT INTO notifications (user_id, notification_type, reference_id, title, message, scheduled_time)
       VALUES ($1,'bounty',$2,'Bounty Fulfilled',$3,NOW())`,
      [bounty.rows[0].requester_id, bountyId,
       `Someone uploaded a resource for your ${bounty.rows[0].course_code} bounty.`]
    );
    res.json({ success: true, fulfillment: fulfillment.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/library/bounties/:id — requester cancels
app.delete('/api/library/bounties/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM library_bounties WHERE id=$1 AND requester_id=$2 RETURNING id`,
      [req.params.id, req.user.userId]
    );
    if (!result.rowCount) return res.status(403).json({ success: false, message: 'Not found or unauthorized' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// EVENT RSVPs
// ============================================================================

// POST /api/school-events/:id/rsvp — going / maybe / not_going
app.post('/api/school-events/:id/rsvp', authMiddleware, async (req, res) => {
  const { status } = req.body;
  const validStatuses = ['going', 'maybe', 'not_going'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid RSVP status' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO event_rsvps (event_id, user_id, status)
       VALUES ($1,$2,$3)
       ON CONFLICT (event_id, user_id) DO UPDATE SET status=$3
       RETURNING *`,
      [req.params.id, req.user.userId, status]
    );
    // Count updated attendance
    const counts = await pool.query(
      `SELECT status, COUNT(*) FROM event_rsvps WHERE event_id=$1 GROUP BY status`,
      [req.params.id]
    );
    res.json({ success: true, rsvp: result.rows[0], counts: counts.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/school-events/:id/rsvps
app.get('/api/school-events/:id/rsvps', authMiddleware, async (req, res) => {
  try {
    const counts = await pool.query(
      `SELECT status, COUNT(*) FROM event_rsvps WHERE event_id=$1 GROUP BY status`,
      [req.params.id]
    );
    const myRsvp = await pool.query(
      `SELECT status FROM event_rsvps WHERE event_id=$1 AND user_id=$2`,
      [req.params.id, req.user.userId]
    );
    res.json({
      success: true,
      counts: counts.rows,
      myStatus: myRsvp.rows[0]?.status || null,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// NOTIFICATIONS — read-all
// ============================================================================

app.post('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `UPDATE notifications SET read=true, read_at=NOW()
       WHERE user_id=$1 AND read=false`,
      [req.user.userId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/notifications/:id
app.delete('/api/notifications/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM notifications WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.userId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// MARKETPLACE — MISSING / ENHANCED ROUTES
// ============================================================================

// GET /api/marketplace/services/:id
app.get('/api/marketplace/services/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE marketplace_services SET views=views+1 WHERE id=$1', [req.params.id]);
    const result = await pool.query(
      `SELECT ms.*, u.full_name AS provider_name, u.phone AS provider_phone,
              u.profile_image_url AS provider_image,
              (SELECT AVG(rating)::numeric(10,1) FROM reviews WHERE reviewed_user_id=ms.provider_id) AS provider_rating,
              (SELECT COUNT(*) FROM reviews WHERE reviewed_user_id=ms.provider_id) AS provider_review_count
       FROM marketplace_services ms
       JOIN users u ON u.id=ms.provider_id
       WHERE ms.id=$1`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Service not found' });
    res.json({ success: true, service: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PUT /api/marketplace/services/:id
app.put('/api/marketplace/services/:id', authMiddleware, async (req, res) => {
  const { title, description, price, category, serviceCategory, duration, availability } = req.body;
  try {
    const check = await pool.query('SELECT provider_id FROM marketplace_services WHERE id=$1', [req.params.id]);
    if (!check.rows.length) return res.status(404).json({ success: false, message: 'Not found' });
    if (check.rows[0].provider_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    const result = await pool.query(
      `UPDATE marketplace_services
       SET title=$1, description=$2, price=$3, category=$4,
           service_category=$5, duration=$6, availability=$7
       WHERE id=$8 RETURNING *`,
      [title, description, price, category, serviceCategory || 'general', duration, availability, req.params.id]
    );
    res.json({ success: true, service: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/marketplace/services/:id/images — upload images for a service
app.post('/api/marketplace/services/:id/images', authMiddleware, imageUpload.array('images', 5), async (req, res) => {
  try {
    const check = await pool.query('SELECT provider_id FROM marketplace_services WHERE id=$1', [req.params.id]);
    if (!check.rows.length) return res.status(404).json({ success: false, message: 'Not found' });
    if (check.rows[0].provider_id !== req.user.userId) return res.status(403).json({ success: false, message: 'Unauthorized' });
    const urls = [];
    for (const file of (req.files || [])) {
      urls.push(await uploadToSupabase(file, 'marketplace-images', 'services/'));
    }
    await pool.query(
      `UPDATE marketplace_services SET images=array_cat(images, $1::text[]) WHERE id=$2`,
      [urls, req.params.id]
    );
    res.json({ success: true, urls });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/marketplace/my-listings — current user's goods + services
app.get('/api/marketplace/my-listings', authMiddleware, async (req, res) => {
  try {
    const [goods, services] = await Promise.all([
      pool.query(
        'SELECT * FROM marketplace_goods WHERE seller_id=$1 ORDER BY created_at DESC',
        [req.user.userId]
      ),
      pool.query(
        'SELECT * FROM marketplace_services WHERE provider_id=$1 ORDER BY created_at DESC',
        [req.user.userId]
      ),
    ]);
    res.json({ success: true, goods: goods.rows, services: services.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// UPDATED AUTH ROUTES — Login with streak + XP, Profile with XP fields
// These REPLACE the originals that are earlier in the file.
// Express uses the LAST matching route, so placing these here overrides them.
// ============================================================================

// OVERRIDE: POST /api/auth/login — adds streak tracking + daily login XP
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (!result.rows.length) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Streak logic
    const today = new Date().toISOString().slice(0, 10);
    const lastLogin = user.last_login_date ? user.last_login_date.toISOString().slice(0, 10) : null;
    let newStreak = user.login_streak || 0;
    let awardedStreak = false;

    if (lastLogin !== today) {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yday = yesterday.toISOString().slice(0, 10);
      newStreak = lastLogin === yday ? newStreak + 1 : 1;
      await pool.query(
        'UPDATE users SET login_streak=$1, last_login_date=$2 WHERE id=$3',
        [newStreak, today, user.id]
      );
      awardedStreak = true;
      setImmediate(async () => {
        await awardXP(user.id, 'daily_login');
        if (newStreak === 7)  await awardXP(user.id, 'login_streak_7',  'streak:7');
        if (newStreak === 30) await awardXP(user.id, 'login_streak_30', 'streak:30');
      });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'fallback-change-this',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id:              user.id,
        email:           user.email,
        fullName:        user.full_name,
        studentId:       user.student_id,
        institution:     user.institution,
        phone:           user.phone,
        bio:             user.bio,
        isCourseRep:     user.is_course_rep,
        profileImageUrl: user.profile_image_url,
        xpPoints:        user.xp_points || 0,
        level:           user.level || 'Bronze',
        loginStreak:     newStreak,
        onboarded:       !!user.onboarded_at,
        programme:       user.programme,
        yearOfStudy:     user.year_of_study,
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: GET /api/auth/profile — includes XP fields
app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, full_name, student_id, institution, phone, bio,
              profile_image_url, is_course_rep, xp_points, level,
              login_streak, reputation_score, rank_percentile, onboarded_at,
              programme, year_of_study, subjects, study_style, study_times, goals
       FROM users WHERE id=$1`,
      [req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// XP HOOKS — Wrapper routes that award XP on key actions
// These are new routes placed AFTER the originals for the actions below.
// Because some originals already handle the logic, we wrap via middleware.
// ============================================================================

// OVERRIDE: POST /api/library — award XP for resource upload
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
    const fileUrl = await uploadToSupabase(mainFile, 'library-resources', 'documents/');
    let thumbnailUrl = null;
    if (thumbnailFile) {
      thumbnailUrl = await uploadToSupabase(thumbnailFile, 'library-resources', 'thumbnails/');
    }
    const result = await pool.query(
      `INSERT INTO library_resources
       (uploader_id, title, description, subject, category, file_url, thumbnail_url, file_type, file_size)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.userId, title, description, subject,
       category || 'Lecture Notes', fileUrl, thumbnailUrl,
       mainFile.mimetype, mainFile.size]
    );
    setImmediate(() => {
      awardXP(req.user.userId, 'resource_upload', `resource:${result.rows[0].id}`);
      updateStudentRank(req.user.userId);
    });
    res.json({ success: true, resource: result.rows[0] });
  } catch (err) {
    console.error('Library upload error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/homework-help/:id/respond — award XP for answering
app.post('/api/homework-help/:id/respond', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { response } = req.body;
  if (!response?.trim()) return res.status(400).json({ success: false, message: 'Response required' });
  try {
    const result = await pool.query(
      'INSERT INTO homework_responses (help_request_id, responder_id, response) VALUES ($1,$2,$3) RETURNING *',
      [id, req.user.userId, response.trim()]
    );
    await pool.query(
      "UPDATE homework_help SET status='answered' WHERE id=$1 AND status='open'",
      [id]
    );
    // Notify question asker
    const question = await pool.query('SELECT student_id, title FROM homework_help WHERE id=$1', [id]);
    if (question.rows.length) {
      await pool.query(
        `INSERT INTO notifications (user_id, notification_type, reference_id, title, message, scheduled_time)
         VALUES ($1,'homework',$2,'New Answer',$3,NOW())`,
        [question.rows[0].student_id, parseInt(id),
         `Someone answered your question: "${question.rows[0].title}"`]
      );
    }
    setImmediate(() => awardXP(req.user.userId, 'homework_answered', `help:${id}`));
    res.json({ success: true, response: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/study-groups — award XP for creating
app.post('/api/study-groups', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  const { name, description, subject, program, maxMembers, isPrivate, study_mode, year_filter } = req.body;
  if (!name) return res.status(400).json({ success: false, message: 'Group name required' });
  try {
    const result = await pool.query(
      `INSERT INTO study_groups
         (creator_id, name, description, subject, program, max_members, is_private, study_mode, year_filter)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [uid, name, description||null, subject||null, program||null,
       maxMembers||50, isPrivate||false, study_mode||'social', year_filter||null]
    );
    const group = result.rows[0];
    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id, role) VALUES ($1,$2,$3)',
      [group.id, uid, 'admin']
    );
    setImmediate(() => awardXP(uid, 'study_group_created', `group:${group.id}`));
    res.json({ success: true, group });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/class-spaces/:id/join — award XP for joining
app.post('/api/class-spaces/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const classExists = await pool.query('SELECT id FROM class_spaces WHERE id=$1', [id]);
    if (!classExists.rows.length) {
      return res.status(404).json({ success: false, message: 'Class not found' });
    }
    const existing = await pool.query(
      'SELECT id FROM class_space_members WHERE class_space_id=$1 AND user_id=$2',
      [id, req.user.userId]
    );
    const alreadyMember = existing.rows.length > 0;
    await pool.query(
      'INSERT INTO class_space_members (class_space_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [id, req.user.userId]
    );
    if (!alreadyMember) {
      setImmediate(() => awardXP(req.user.userId, 'class_joined', `class:${id}`));
    }
    res.json({ success: true, message: 'Joined class space' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/marketplace/goods — award XP for listing
app.post('/api/marketplace/goods', authMiddleware, imageUpload.array('images', 5), async (req, res) => {
  const { title, description, price, category, condition, location } = req.body;
  try {
    const imageUrls = [];
    for (const file of (req.files || [])) {
      imageUrls.push(await uploadToSupabase(file, 'marketplace-images', 'goods/'));
    }
    const result = await pool.query(
      'INSERT INTO marketplace_goods (seller_id, title, description, price, category, condition, location, images) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [req.user.userId, title, description, price, category, condition, location, imageUrls]
    );
    setImmediate(() => awardXP(req.user.userId, 'item_listed', `good:${result.rows[0].id}`));
    res.json({ success: true, item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/reviews — award XP for leaving a review
app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { itemId, rating, comment, reviewedUserId } = req.body;
  if (!itemId || !rating) return res.status(400).json({ success: false, message: 'Item ID and rating required' });
  try {
    const insert = await pool.query(
      `INSERT INTO reviews (marketplace_item_id, reviewer_id, reviewed_user_id, rating, comment)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, marketplace_item_id, reviewer_id, rating, comment, created_at`,
      [itemId, req.user.userId, reviewedUserId, rating, comment]
    );
    const review = insert.rows[0];
    const withUser = await pool.query(
      `SELECT $1::int AS id, $2::int AS reviewer_id, $3::int AS marketplace_item_id,
              $4::int AS rating, $5::text AS comment, $6::timestamp AS created_at,
              u.full_name AS reviewer_name, u.profile_image_url AS reviewer_image
       FROM users u WHERE u.id=$2`,
      [review.id, review.reviewer_id, review.marketplace_item_id,
       review.rating, review.comment, review.created_at]
    );
    setImmediate(() => awardXP(req.user.userId, 'review_given', `review:${review.id}`));
    res.json({ success: true, review: withUser.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/assignments/:id/submit — award XP
app.post('/api/assignments/:id/submit', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE assignments SET status='submitted', submitted_at=NOW()
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Assignment not found' });
    setImmediate(() => awardXP(req.user.userId, 'assignment_submitted', `assignment:${req.params.id}`));
    res.json({ success: true, assignment: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/study-tasks/:taskId/complete — award XP
app.post('/api/study-tasks/:taskId/complete', authMiddleware, async (req, res) => {
  const { notes } = req.body;
  try {
    const result = await pool.query(
      `UPDATE study_tasks st
       SET completed=true, completed_at=NOW(), notes=$1
       FROM study_plans sp
       WHERE st.id=$2 AND st.study_plan_id=sp.id AND sp.user_id=$3
       RETURNING st.*`,
      [notes, req.params.taskId, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Task not found' });
    await pool.query(
      `UPDATE study_plans sp
       SET progress_percentage=(
         SELECT (COUNT(*) FILTER (WHERE completed=true)::DECIMAL / COUNT(*))*100
         FROM study_tasks WHERE study_plan_id=sp.id
       )
       WHERE id=(SELECT study_plan_id FROM study_tasks WHERE id=$1)`,
      [req.params.taskId]
    );
    setImmediate(() => awardXP(req.user.userId, 'study_task_completed', `task:${req.params.taskId}`));
    res.json({ success: true, task: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/library/:id/upvote — award XP to uploader when upvoted
app.post('/api/library/:id/upvote', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const existing = await pool.query(
      "SELECT id FROM library_interactions WHERE user_id=$1 AND resource_id=$2 AND interaction_type='upvote'",
      [req.user.userId, id]
    );
    if (existing.rows.length) {
      await pool.query('DELETE FROM library_interactions WHERE id=$1', [existing.rows[0].id]);
      return res.json({ success: true, action: 'removed' });
    }
    await pool.query(
      "INSERT INTO library_interactions (user_id, resource_id, interaction_type) VALUES ($1,$2,'upvote')",
      [req.user.userId, id]
    );
    // Award XP to uploader
    const uploader = await pool.query('SELECT uploader_id FROM library_resources WHERE id=$1', [id]);
    if (uploader.rows.length && uploader.rows[0].uploader_id !== req.user.userId) {
      setImmediate(() => {
        awardXP(uploader.rows[0].uploader_id, 'upvote_received', `resource:${id}`);
        awardXP(req.user.userId, 'library_upvote_given', `resource:${id}`);
      });
    }
    res.json({ success: true, action: 'added' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// STUDY GROUPS — JOIN (separate from create, awards join XP)
// ============================================================================
app.post('/api/study-groups/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const uid = req.user.userId;
  try {
    const group = await pool.query(
      'SELECT id, max_members FROM study_groups WHERE id=$1',
      [id]
    );
    if (!group.rows.length) return res.status(404).json({ success: false, message: 'Group not found' });
    const memberCount = await pool.query(
      'SELECT COUNT(*) FROM study_group_members WHERE group_id=$1',
      [id]
    );
    if (parseInt(memberCount.rows[0].count) >= group.rows[0].max_members) {
      return res.status(400).json({ success: false, message: 'Group is full' });
    }
    const existing = await pool.query(
      'SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2',
      [id, uid]
    );
    if (existing.rows.length) {
      return res.status(400).json({ success: false, message: 'Already a member' });
    }
    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id, role) VALUES ($1,$2,$3)',
      [id, uid, 'member']
    );
    setImmediate(() => awardXP(uid, 'study_group_joined', `group:${id}`));
    res.json({ success: true, message: 'Joined group' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// COMMENT LIKES
// ============================================================================

app.post('/api/library/comments/:id/like', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  try {
    const existing = await pool.query(
      'SELECT id FROM library_comment_likes WHERE comment_id=$1 AND user_id=$2',
      [req.params.id, uid]
    );
    if (existing.rows.length) {
      await pool.query('DELETE FROM library_comment_likes WHERE id=$1', [existing.rows[0].id]);
      return res.json({ success: true, liked: false });
    }
    await pool.query(
      'INSERT INTO library_comment_likes (comment_id, user_id) VALUES ($1,$2)',
      [req.params.id, uid]
    );
    res.json({ success: true, liked: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// PROFILE — update with all onboarding + extended fields
// ============================================================================

app.patch('/api/auth/profile', authMiddleware, async (req, res) => {
  const { fullName, studentId, institution, phone, bio, programme, yearOfStudy } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users
       SET full_name=$1, student_id=$2, institution=$3, phone=$4, bio=$5,
           programme=$6, year_of_study=$7, updated_at=NOW()
       WHERE id=$8
       RETURNING id, email, full_name, student_id, institution, phone, bio,
                 is_course_rep, programme, year_of_study, xp_points, level`,
      [fullName, studentId, institution, phone, bio,
       programme||null, yearOfStudy||null, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user: result.rows[0], message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// TIMETABLE — PATCH (missing in original, added here properly)
// ============================================================================

app.patch('/api/timetable/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  const allowed = ['title','day_of_week','start_time','end_time','location',
                   'course_code','instructor','notes','color','notification_enabled',
                   'notification_minutes_before','building','room_number'];
  try {
    const fields = [];
    const values = [];
    let n = 1;
    for (const key of allowed) {
      if (updates[key] !== undefined) {
        fields.push(`${key}=$${n++}`);
        values.push(updates[key]);
      }
    }
    if (!fields.length) return res.status(400).json({ success: false, message: 'No valid fields provided' });
    values.push(id, req.user.userId);
    const result = await pool.query(
      `UPDATE timetables SET ${fields.join(',')}
       WHERE id=$${n} AND user_id=$${n+1} RETURNING *`,
      values
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Entry not found' });
    res.json({ success: true, entry: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// MISC UTILITY ROUTES
// ============================================================================

// GET /api/stats/platform — public platform stats
app.get('/api/stats/platform', async (req, res) => {
  try {
    const [users, resources, groups, events] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM library_resources WHERE is_public=true'),
      pool.query('SELECT COUNT(*) FROM study_groups WHERE is_private=false'),
      pool.query('SELECT COUNT(*) FROM school_events'),
    ]);
    res.json({
      success: true,
      stats: {
        totalUsers:     parseInt(users.rows[0].count),
        totalResources: parseInt(resources.rows[0].count),
        totalGroups:    parseInt(groups.rows[0].count),
        totalEvents:    parseInt(events.rows[0].count),
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/library/:id — get single resource detail
app.get('/api/library/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lr.*, u.full_name AS uploader_name, u.profile_image_url AS uploader_image,
              (SELECT COUNT(*) FROM library_interactions WHERE resource_id=lr.id AND interaction_type='upvote') AS upvotes,
              (SELECT COUNT(*) FROM library_interactions WHERE resource_id=lr.id AND interaction_type='downvote') AS downvotes,
              EXISTS(SELECT 1 FROM library_interactions WHERE resource_id=lr.id AND user_id=$2 AND interaction_type='upvote') AS has_upvoted,
              EXISTS(SELECT 1 FROM library_bookmarks WHERE resource_id=lr.id AND user_id=$2) AS is_bookmarked
       FROM library_resources lr
       JOIN users u ON u.id=lr.uploader_id
       WHERE lr.id=$1 AND (lr.is_public=true OR lr.uploader_id=$2)`,
      [req.params.id, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Resource not found' });
    // Increment download counter on fetch
    await pool.query('UPDATE library_resources SET downloads=downloads+1 WHERE id=$1', [req.params.id]);
    res.json({ success: true, resource: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Seed badges on startup (non-blocking)
setImmediate(async () => {
  try { await seedBadges(); } catch (_) {}
});
// ============================================================
// MISSING ROUTES PATCH
// Paste this block BEFORE the `app.use((req, res) => { 404... })` line
// ============================================================

// ── DAILY QUESTS ─────────────────────────────────────────────
app.get('/api/daily-quests', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  try {
    const today = new Date().toISOString().split('T')[0];
    // Seed default quests for today if none exist
    await pool.query(`
      INSERT INTO daily_quests (user_id, quest_type, label, target, progress, date)
      VALUES
        ($1, 'upload_resource',   'Upload a resource',       1, 0, $2),
        ($1, 'join_study_group',  'Join a study session',    1, 0, $2),
        ($1, 'send_message',      'Send 5 messages',         5, 0, $2),
        ($1, 'complete_task',     'Complete 3 tasks',        3, 0, $2),
        ($1, 'daily_login',       'Log in today',            1, 1, $2)
      ON CONFLICT (user_id, quest_type, date) DO NOTHING
    `, [userId, today]);

    const { rows } = await pool.query(
      `SELECT * FROM daily_quests WHERE user_id = $1 AND date = $2 ORDER BY id`,
      [userId, today]
    );
    res.json({ success: true, quests: rows });
  } catch (err) {
    // Table may not exist yet — return empty gracefully
    console.error('daily-quests error:', err.message);
    res.json({ success: true, quests: [] });
  }
});

app.post('/api/daily-quests/progress', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { questType, increment = 1 } = req.body;
  const today = new Date().toISOString().split('T')[0];
  try {
    await pool.query(`
      UPDATE daily_quests
      SET progress = LEAST(progress + $1, target)
      WHERE user_id = $2 AND quest_type = $3 AND date = $4
    `, [increment, userId, questType, today]);
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true });
  }
});

// Ensure daily_quests table exists
pool.query(`
  CREATE TABLE IF NOT EXISTS daily_quests (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    quest_type VARCHAR(60) NOT NULL,
    label      TEXT NOT NULL,
    target     INTEGER DEFAULT 1,
    progress   INTEGER DEFAULT 0,
    xp_reward  INTEGER DEFAULT 20,
    date       DATE NOT NULL DEFAULT CURRENT_DATE,
    UNIQUE(user_id, quest_type, date)
  )
`).catch(() => {});

// ── HABITS ───────────────────────────────────────────────────
app.get('/api/habits', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  try {
    // Seed default habits if user has none
    await pool.query(`
      INSERT INTO habits (user_id, label, icon, frequency)
      VALUES
        ($1, 'Review notes',     '📖', 'daily'),
        ($1, 'Drink water',      '💧', 'daily'),
        ($1, 'Exercise',         '🏃', 'daily'),
        ($1, 'Read ahead',       '📚', 'daily')
      ON CONFLICT DO NOTHING
    `, [userId]);

    const today = new Date().toISOString().split('T')[0];
    const { rows } = await pool.query(`
      SELECT h.*,
        EXISTS(
          SELECT 1 FROM habit_logs hl
          WHERE hl.habit_id = h.id AND hl.date = $2
        ) AS completed_today
      FROM habits h
      WHERE h.user_id = $1
      ORDER BY h.id
    `, [userId, today]);
    res.json({ success: true, habits: rows });
  } catch (err) {
    console.error('habits error:', err.message);
    res.json({ success: true, habits: [] });
  }
});

app.post('/api/habits/toggle', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { habitId } = req.body;
  const today = new Date().toISOString().split('T')[0];
  try {
    const existing = await pool.query(
      `SELECT id FROM habit_logs WHERE habit_id = $1 AND date = $2`,
      [habitId, today]
    );
    if (existing.rows.length) {
      await pool.query(`DELETE FROM habit_logs WHERE habit_id = $1 AND date = $2`, [habitId, today]);
      res.json({ success: true, completed: false });
    } else {
      await pool.query(`INSERT INTO habit_logs (habit_id, user_id, date) VALUES ($1,$2,$3)`, [habitId, userId, today]);
      res.json({ success: true, completed: true });
    }
  } catch (err) {
    res.json({ success: true, completed: false });
  }
});

// Ensure habits tables exist
pool.query(`
  CREATE TABLE IF NOT EXISTS habits (
    id        SERIAL PRIMARY KEY,
    user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
    label     VARCHAR(120) NOT NULL,
    icon      VARCHAR(10) DEFAULT '✅',
    frequency VARCHAR(20) DEFAULT 'daily',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS habit_logs (
    id        SERIAL PRIMARY KEY,
    habit_id  INTEGER REFERENCES habits(id) ON DELETE CASCADE,
    user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
    date      DATE NOT NULL DEFAULT CURRENT_DATE,
    UNIQUE(habit_id, date)
  );
`).catch(() => {});

// ── ACTIVITY FEED ─────────────────────────────────────────────
app.get('/api/activity/feed', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  try {
    const { rows } = await pool.query(`
      SELECT al.*, u.full_name, u.avatar_url
      FROM activity_logs al
      JOIN users u ON al.user_id = u.id
      WHERE al.user_id = $1
         OR al.user_id IN (
           SELECT friend_id FROM friendships WHERE user_id = $1 AND status = 'accepted'
           UNION
           SELECT user_id FROM friendships WHERE friend_id = $1 AND status = 'accepted'
         )
      ORDER BY al.created_at DESC
      LIMIT $2
    `, [userId, limit]);
    res.json({ success: true, feed: rows });
  } catch (err) {
    console.error('activity feed error:', err.message);
    res.json({ success: true, feed: [] });
  }
});

app.get('/api/activity/me', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  try {
    const { rows } = await pool.query(
      `SELECT * FROM activity_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [userId, limit]
    );
    res.json({ success: true, activity: rows });
  } catch (err) {
    res.json({ success: true, activity: [] });
  }
});

app.post('/api/activity', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { action, label, meta } = req.body;
  try {
    await pool.query(
      `INSERT INTO activity_logs (user_id, action, label, meta) VALUES ($1,$2,$3,$4)`,
      [userId, action, label, JSON.stringify(meta || {})]
    );
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true });
  }
});

// Ensure activity_logs table exists
pool.query(`
  CREATE TABLE IF NOT EXISTS activity_logs (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    action     VARCHAR(80),
    label      TEXT,
    meta       JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`).catch(() => {});

// ── DASHBOARD ─────────────────────────────────────────────────
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  try {
    const [userRes, tasksRes, eventsRes] = await Promise.all([
      pool.query(
        `SELECT id, full_name, avatar_url, xp_points, level, login_streak, department, year_of_study
         FROM users WHERE id = $1`, [userId]
      ),
      pool.query(
        `SELECT id, title, due_date, status FROM assignments
         WHERE user_id = $1 AND status != 'completed'
         ORDER BY due_date ASC LIMIT 5`, [userId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT id, title, event_date FROM events
         WHERE user_id = $1 AND event_date >= NOW()
         ORDER BY event_date ASC LIMIT 3`, [userId]
      ).catch(() => ({ rows: [] })),
    ]);

    res.json({
      success: true,
      user: userRes.rows[0] || {},
      upcomingTasks: tasksRes.rows,
      upcomingEvents: eventsRes.rows,
    });
  } catch (err) {
    console.error('dashboard error:', err.message);
    res.json({ success: true, user: {}, upcomingTasks: [], upcomingEvents: [] });
  }
});

// ── SUGGESTIONS ───────────────────────────────────────────────
app.get('/api/suggestions', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  try {
    // Suggest people in same department/year not yet friends
    const { rows } = await pool.query(`
      SELECT u.id, u.full_name, u.avatar_url, u.department, u.year_of_study, u.level
      FROM users u
      WHERE u.id != $1
        AND u.id NOT IN (
          SELECT friend_id FROM friendships WHERE user_id = $1
          UNION SELECT user_id FROM friendships WHERE friend_id = $1
        )
        AND (
          u.department = (SELECT department FROM users WHERE id = $1)
          OR u.year_of_study = (SELECT year_of_study FROM users WHERE id = $1)
        )
      ORDER BY RANDOM()
      LIMIT 6
    `, [userId]);
    res.json({ success: true, suggestions: rows });
  } catch (err) {
    console.error('suggestions error:', err.message);
    res.json({ success: true, suggestions: [] });
  }
});

// ── CLASS SPACE CHAT ──────────────────────────────────────────
app.get('/api/chat/class/:classId/messages', authMiddleware, async (req, res) => {
  const { classId } = req.params;
  const userId = req.user.userId;
  try {
    // Verify membership
    const member = await pool.query(
      `SELECT 1 FROM class_space_members WHERE class_space_id = $1 AND user_id = $2`,
      [classId, userId]
    );
    if (!member.rows.length) {
      return res.status(403).json({ success: false, message: 'Not a member of this class' });
    }
    const { rows } = await pool.query(`
      SELECT cm.*, u.full_name AS sender_name, u.avatar_url AS sender_avatar
      FROM chat_messages cm
      JOIN users u ON cm.sender_id = u.id
      WHERE cm.group_id = $1
      ORDER BY cm.created_at ASC
      LIMIT 100
    `, [classId]);
    res.json({ success: true, messages: rows });
  } catch (err) {
    console.error('class messages error:', err.message);
    res.json({ success: true, messages: [] });
  }
});

app.post('/api/chat/class/:classId/messages', authMiddleware, async (req, res) => {
  const { classId } = req.params;
  const userId = req.user.userId;
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ success: false, message: 'Message required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO chat_messages (sender_id, group_id, message) VALUES ($1,$2,$3) RETURNING *`,
      [userId, classId, message.trim()]
    );
    res.json({ success: true, message: rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── DAILY LOGIN TRACK (for Navigation.js trackDailyLogin) ─────
app.post('/api/daily-login', authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  try {
    await pool.query(`
      UPDATE users SET
        last_login = NOW(),
        login_streak = CASE
          WHEN DATE(last_login) = CURRENT_DATE - INTERVAL '1 day' THEN login_streak + 1
          WHEN DATE(last_login) = CURRENT_DATE THEN login_streak
          ELSE 1
        END
      WHERE id = $1
    `, [userId]);
    // Award XP
    await pool.query(
      `UPDATE users SET xp_points = xp_points + 10 WHERE id = $1`, [userId]
    ).catch(() => {});
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true });
  }
});

// ============================================================
// END MISSING ROUTES PATCH
// ============================================================
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

// ============================================================================
// V4: PEER RECOMMENDATIONS ENGINE
// ============================================================================

app.get('/api/recommendations/peers', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  try {
    // Get current user's profile
    const { rows: [me] } = await pool.query(
      `SELECT department, year_of_study, institution, study_style, noise_pref, interests, study_times, academic_goals
       FROM users WHERE id = $1`, [uid]
    );
    if (!me) return res.json({ success: true, peers: [] });

    const interests = me.interests || [];
    const goals = me.academic_goals || [];
    const studyTimes = me.study_times || [];

    // Find candidates in same institution + department, exclude self + already following
    const { rows: candidates } = await pool.query(
      `SELECT u.id, u.full_name, u.department, u.year_of_study, u.institution, u.bio,
              u.study_style, u.noise_pref, u.interests, u.study_times, u.academic_goals,
              u.xp_points, u.level, u.profile_image_url, u.phone,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=u.id) AS is_following
       FROM users u
       WHERE u.id != $1
         AND u.institution ILIKE $2
       ORDER BY u.xp_points DESC
       LIMIT 100`,
      [uid, `%${me.institution || ''}%`]
    );

    // Score each candidate
    const scored = candidates.map(p => {
      let score = 0;
      const reasons = [];

      if (p.department === me.department) { score += 35; reasons.push('Same dept'); }
      if (p.year_of_study === me.year_of_study) { score += 20; reasons.push('Same year'); }
      if (p.study_style === me.study_style && p.study_style) { score += 15; reasons.push('Same study style'); }
      if (p.noise_pref === me.noise_pref && p.noise_pref) { score += 10; reasons.push('Same environment'); }

      // Shared interests
      const pInterests = Array.isArray(p.interests) ? p.interests : (JSON.parse(p.interests || '[]'));
      const shared = pInterests.filter(i => interests.includes(i));
      if (shared.length > 0) { score += Math.min(shared.length * 5, 15); reasons.push(`${shared.length} shared interests`); }

      // Shared study times
      const pTimes = Array.isArray(p.study_times) ? p.study_times : (JSON.parse(p.study_times || '[]'));
      const sharedTimes = pTimes.filter(t => studyTimes.includes(t));
      if (sharedTimes.length > 0) { score += 5; reasons.push('Similar schedule'); }

      // Shared goals
      const pGoals = Array.isArray(p.academic_goals) ? p.academic_goals : (JSON.parse(p.academic_goals || '[]'));
      const sharedGoals = pGoals.filter(g => goals.includes(g));
      if (sharedGoals.length > 0) { score += Math.min(sharedGoals.length * 3, 10); }

      return { ...p, match_score: Math.min(score, 100), match_reasons: reasons.slice(0,3) };
    });

    // Sort by score, exclude 0-score results
    const sorted = scored.filter(p => p.match_score > 10).sort((a,b) => b.match_score - a.match_score).slice(0, 20);
    res.json({ success: true, peers: sorted });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// V4: PHONE CONTACTS MATCHING
// ============================================================================

app.post('/api/contacts/find', authMiddleware, async (req, res) => {
  const { phones } = req.body;
  if (!Array.isArray(phones) || phones.length === 0) {
    return res.status(400).json({ success: false, message: 'phones array required' });
  }
  const uid = req.user.userId;
  try {
    // Normalise phones — strip spaces and dashes
    const normalised = phones.map(p => p.replace(/[\s\-().]/g, ''));
    const { rows } = await pool.query(
      `SELECT u.id, u.full_name, u.department, u.year_of_study, u.institution, u.bio,
              u.phone, u.xp_points, u.level,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=u.id) AS is_following
       FROM users u
       WHERE u.id != $1 AND replace(replace(replace(u.phone,' ',''),'-',''),'(','') = ANY($2::text[])`,
      [uid, normalised]
    );
    res.json({ success: true, matches: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// V4: USER PREFERENCES
// ============================================================================

app.get('/api/preferences', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM user_preferences WHERE user_id=$1', [req.user.userId]);
    res.json({ success: true, preferences: rows[0] || null });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.put('/api/preferences', authMiddleware, async (req, res) => {
  const { studyStyle, noisePref, collabPref, interests, studyTimes, goals, notificationsEnabled, focusLockEnabled, weeklyFocusGoalMins } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO user_preferences(user_id, study_style, noise_pref, collab_pref, interests, study_times, goals,
         notifications_enabled, focus_lock_enabled, weekly_focus_goal_mins, updated_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
       ON CONFLICT(user_id) DO UPDATE SET
         study_style=$2, noise_pref=$3, collab_pref=$4, interests=$5, study_times=$6, goals=$7,
         notifications_enabled=$8, focus_lock_enabled=$9, weekly_focus_goal_mins=$10, updated_at=NOW()
       RETURNING *`,
      [req.user.userId, studyStyle||'visual', noisePref||'quiet', collabPref||'both',
       JSON.stringify(interests||[]), JSON.stringify(studyTimes||[]), JSON.stringify(goals||[]),
       notificationsEnabled!==false, focusLockEnabled||false, weeklyFocusGoalMins||600]
    );
    if (interests) await pool.query('UPDATE users SET interests=$1 WHERE id=$2', [JSON.stringify(interests), req.user.userId]);
    if (studyStyle) await pool.query('UPDATE users SET study_style=$1 WHERE id=$2', [studyStyle, req.user.userId]);
    res.json({ success: true, preferences: rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// V4: ADMIN EXAM SCHEDULES
// ============================================================================

app.post('/api/admin/exam-schedules', authMiddleware, async (req, res) => {
  const { rows: [admin] } = await pool.query('SELECT is_admin FROM users WHERE id=$1', [req.user.userId]);
  if (!admin?.is_admin) return res.status(403).json({ success: false, message: 'Admin only' });

  const { institution, department, program, yearOfStudy, semester, academicYear, exams } = req.body;
  if (!institution || !Array.isArray(exams)) return res.status(400).json({ success: false, message: 'institution + exams required' });

  try {
    const inserted = [];
    for (const e of exams) {
      const { rows } = await pool.query(
        `INSERT INTO admin_exam_schedules(admin_id, course_code, course_name, institution, department, program,
           year_of_study, exam_date, start_time, end_time, venue, semester, academic_year, notes)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,
        [req.user.userId, e.courseCode||null, e.courseName, institution, department||null, program||null,
         yearOfStudy||null, e.examDate||null, e.startTime||null, e.endTime||null, e.venue||null,
         semester||null, academicYear||null, e.notes||null]
      );
      inserted.push(rows[0].id);
    }
    // Push notifications to matching students
    if (program || department) {
      const { rows: students } = await pool.query(
        `SELECT id FROM users WHERE institution ILIKE $1 AND (department=$2 OR year_of_study=$3) AND id != $4 LIMIT 500`,
        [`%${institution}%`, department||'', yearOfStudy||'', req.user.userId]
      );
      for (const s of students) {
        await pool.query(
          `INSERT INTO notifications(user_id, type, title, body, link_page)
           VALUES($1,'exam_schedule','📝 New Exam Schedule','Admin has uploaded a new exam schedule for your program. Check your timetable.','timetable')`,
          [s.id]
        );
      }
    }
    res.json({ success: true, inserted: inserted.length });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/admin/exam-schedules', authMiddleware, async (req, res) => {
  const { rows: [admin] } = await pool.query('SELECT is_admin FROM users WHERE id=$1', [req.user.userId]);
  if (!admin?.is_admin) return res.status(403).json({ success: false, message: 'Admin only' });
  try {
    const { rows } = await pool.query(
      `SELECT aes.*, u.full_name as admin_name,
              COUNT(aes.id) OVER (PARTITION BY aes.institution, aes.program, aes.semester) as exam_count
       FROM admin_exam_schedules aes
       LEFT JOIN users u ON aes.admin_id = u.id
       ORDER BY aes.created_at DESC LIMIT 100`
    );
    res.json({ success: true, schedules: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// GET /api/my-exam-schedule — student's exam schedule from admin uploads
app.get('/api/my-exam-schedule', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  try {
    const { rows: [me] } = await pool.query('SELECT institution, department, year_of_study FROM users WHERE id=$1', [uid]);
    if (!me) return res.json({ success: true, exams: [] });

    const { rows } = await pool.query(
      `SELECT * FROM admin_exam_schedules
       WHERE institution ILIKE $1
         AND (department IS NULL OR department = $2)
         AND (year_of_study IS NULL OR year_of_study = $3)
       ORDER BY exam_date ASC`,
      [`%${me.institution||''}%`, me.department||'', me.year_of_study||'']
    );
    res.json({ success: true, exams: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// V4: ONBOARDING ENDPOINT
// ============================================================================

app.post('/api/onboarding', authMiddleware, async (req, res) => {
  const {
    department, yearOfStudy, program, courses, studyTimes, studyStyle,
    noisePref, collabPref, interests, academicGoals, phone, notificationPrefs, bio, onboardingComplete
  } = req.body;
  const uid = req.user.userId;
  try {
    // Update core user fields
    await pool.query(
      `UPDATE users SET
         department = COALESCE($1, department),
         year_of_study = COALESCE($2, year_of_study),
         study_style = COALESCE($3, study_style),
         noise_pref = COALESCE($4, noise_pref),
         collab_pref = COALESCE($5, collab_pref),
         interests = COALESCE($6::jsonb, interests),
         study_times = COALESCE($7::jsonb, study_times),
         academic_goals = COALESCE($8::jsonb, academic_goals),
         bio = COALESCE($9, bio),
         onboarding_complete = COALESCE($10, onboarding_complete),
         updated_at = NOW()
       WHERE id = $11`,
      [department||null, yearOfStudy||null, studyStyle||null, noisePref||null, collabPref||null,
       interests||null, studyTimes||null, academicGoals||null, bio||null, onboardingComplete||null, uid]
    );

    // Update phone if provided (check uniqueness)
    if (phone) {
      const { rows: existing } = await pool.query('SELECT id FROM users WHERE phone=$1 AND id!=$2', [phone, uid]);
      if (!existing.length) {
        await pool.query('UPDATE users SET phone=$1 WHERE id=$2', [phone, uid]);
      }
    }

    // Save preferences
    await pool.query(
      `INSERT INTO user_preferences(user_id, study_style, noise_pref, collab_pref, interests, study_times, goals, updated_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
       ON CONFLICT(user_id) DO UPDATE SET
         study_style=$2, noise_pref=$3, collab_pref=$4, interests=$5, study_times=$6, goals=$7, updated_at=NOW()`,
      [uid, studyStyle||'visual', noisePref||'quiet', collabPref||'both',
       interests||'[]', studyTimes||'[]', academicGoals||'[]']
    );

    // Get updated user
    const { rows: [user] } = await pool.query(
      'SELECT id, email, full_name, student_id, institution, phone, bio, department, year_of_study, onboarding_complete, xp_points, level FROM users WHERE id=$1',
      [uid]
    );
    res.json({ success: true, user });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// V4: UNIVERSAL SEARCH
// ============================================================================

app.get('/api/search', authMiddleware, async (req, res) => {
  const { q, types } = req.query;
  if (!q || q.length < 2) return res.status(400).json({ success: false, message: 'Query too short' });
  const uid = req.user.userId;
  const term = `%${q}%`;

  try {
    const results = {};

    // Users
    const { rows: users } = await pool.query(
      `SELECT id, full_name, department, year_of_study, institution, bio, xp_points, level
       FROM users WHERE (full_name ILIKE $1 OR student_id ILIKE $1) AND id!=$2 LIMIT 5`,
      [term, uid]
    );
    results.users = users;

    // Library resources
    const { rows: resources } = await pool.query(
      `SELECT id, title, description, subject, course_code, resource_type, download_count, upvotes
       FROM library_resources WHERE title ILIKE $1 OR subject ILIKE $1 OR course_code ILIKE $1 ORDER BY upvotes DESC LIMIT 5`,
      [term]
    );
    results.resources = resources;

    // Homework help
    const { rows: questions } = await pool.query(
      `SELECT hh.id, hh.title, hh.status, hh.subject, u.full_name as student_name
       FROM homework_help hh JOIN users u ON hh.student_id=u.id
       WHERE hh.title ILIKE $1 OR hh.question ILIKE $1 ORDER BY hh.created_at DESC LIMIT 5`,
      [term]
    );
    results.questions = questions;

    // Study groups
    const { rows: groups } = await pool.query(
      `SELECT sg.id, sg.name, sg.description, sg.subject, sg.meeting_style,
              COUNT(sgm.user_id) as member_count
       FROM study_groups sg LEFT JOIN study_group_members sgm ON sg.id=sgm.study_group_id
       WHERE sg.name ILIKE $1 OR sg.subject ILIKE $1
       GROUP BY sg.id ORDER BY member_count DESC LIMIT 5`,
      [term]
    );
    results.groups = groups;

    // Class spaces
    const { rows: classes } = await pool.query(
      `SELECT id, course_code, course_name, description, semester
       FROM class_spaces WHERE course_name ILIKE $1 OR course_code ILIKE $1 LIMIT 5`,
      [term]
    );
    results.classes = classes;

    // Campus posts
    const { rows: posts } = await pool.query(
      `SELECT cp.id, cp.content, cp.created_at, u.full_name as author_name
       FROM campus_posts cp JOIN users u ON cp.author_id=u.id
       WHERE cp.content ILIKE $1 ORDER BY cp.created_at DESC LIMIT 5`,
      [term]
    );
    results.posts = posts;

    // Log search
    await pool.query(
      'INSERT INTO search_history(user_id, query, result_count) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
      [uid, q, Object.values(results).reduce((s, a) => s + a.length, 0)]
    ).catch(() => {});

    res.json({ success: true, query: q, results });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// V4: HOMEWORK RESPONSE UPVOTE + MARK ANSWERED
// ============================================================================

app.post('/api/homework-responses/:id/upvote', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows: existing } = await pool.query(
      'SELECT 1 FROM homework_response_upvotes WHERE response_id=$1 AND user_id=$2', [id, req.user.userId]
    );
    if (existing.length) {
      await pool.query('DELETE FROM homework_response_upvotes WHERE response_id=$1 AND user_id=$2', [id, req.user.userId]);
      await pool.query('UPDATE homework_responses SET upvotes=GREATEST(upvotes-1,0) WHERE id=$1', [id]);
      return res.json({ success: true, action: 'removed' });
    }
    await pool.query('INSERT INTO homework_response_upvotes(response_id, user_id) VALUES($1,$2)', [id, req.user.userId]);
    await pool.query('UPDATE homework_responses SET upvotes=upvotes+1 WHERE id=$1', [id]);
    res.json({ success: true, action: 'added' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/homework-help/:id/mark-answered', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { responseId } = req.body;
  try {
    await pool.query('UPDATE homework_responses SET is_accepted=false WHERE help_request_id=$1', [id]);
    if (responseId) await pool.query('UPDATE homework_responses SET is_accepted=true WHERE id=$1', [responseId]);
    await pool.query("UPDATE homework_help SET status='answered' WHERE id=$1 AND student_id=$2", [id, req.user.userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// V4: MIGRATE
// ============================================================================

app.post('/api/migrate-v4', async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_preferences (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        study_style VARCHAR(30) DEFAULT 'visual',
        noise_pref VARCHAR(20) DEFAULT 'quiet',
        collab_pref VARCHAR(20) DEFAULT 'both',
        interests JSONB DEFAULT '[]',
        study_times JSONB DEFAULT '[]',
        goals JSONB DEFAULT '[]',
        notifications_enabled BOOLEAN DEFAULT true,
        focus_lock_enabled BOOLEAN DEFAULT false,
        weekly_focus_goal_mins INTEGER DEFAULT 600,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS phone_contacts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        contact_phone VARCHAR(50) NOT NULL,
        contact_name VARCHAR(200),
        found_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, contact_phone)
      );
      CREATE TABLE IF NOT EXISTS admin_exam_schedules (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        course_code VARCHAR(50),
        course_name VARCHAR(255) NOT NULL,
        institution VARCHAR(255),
        department VARCHAR(100),
        program VARCHAR(100),
        year_of_study VARCHAR(20),
        exam_date TIMESTAMPTZ,
        start_time TIME,
        end_time TIME,
        venue VARCHAR(255),
        semester VARCHAR(50),
        academic_year VARCHAR(20),
        notes TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS homework_response_upvotes (
        id SERIAL PRIMARY KEY,
        response_id INTEGER REFERENCES homework_responses(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(response_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS search_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        query VARCHAR(255) NOT NULL,
        result_count INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      -- Core user profile columns (safe to add if missing)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS institution VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS department VARCHAR(100);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS year_of_study VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_image_url TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT false;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_course_rep BOOLEAN DEFAULT false;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS xp_points INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS level VARCHAR(20) DEFAULT 'Bronze';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS login_streak INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active TIMESTAMPTZ;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS status_emoji VARCHAR(10);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS status_text VARCHAR(100);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS study_times JSONB DEFAULT '[]';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS academic_goals JSONB DEFAULT '[]';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS weekly_focus_goal_mins INTEGER DEFAULT 600;
      -- V4 specific
      ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_complete BOOLEAN DEFAULT false;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS interests JSONB DEFAULT '[]';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS study_style VARCHAR(30);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS noise_pref VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS collab_pref VARCHAR(20);
      ALTER TABLE homework_responses ADD COLUMN IF NOT EXISTS upvotes INTEGER DEFAULT 0;
      ALTER TABLE homework_responses ADD COLUMN IF NOT EXISTS is_accepted BOOLEAN DEFAULT false;
    `);
    res.json({ success: true, message: 'V4 migration complete' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});



// ============================================================================
// V4 ROUTES: Onboarding, Preferences, Tour, Exam Schedules, Contacts, Recommendations
// ============================================================================

// ── MIGRATE V4 ──────────────────────────────────────────────────────────────
app.post('/api/migrate-v4', async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_complete BOOLEAN DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS interests JSONB DEFAULT '[]';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS study_style VARCHAR(30);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS noise_pref VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS social_pref VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS study_hours VARCHAR(10);
      ALTER TABLE homework_help ADD COLUMN IF NOT EXISTS urgency VARCHAR(20) DEFAULT 'normal';
      
      CREATE TABLE IF NOT EXISTS user_preferences (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        study_style VARCHAR(30), noise_pref VARCHAR(20), social_pref VARCHAR(20),
        study_hours VARCHAR(10), interests JSONB DEFAULT '[]',
        academic_goals JSONB DEFAULT '[]', courses JSONB DEFAULT '[]',
        notifications_enabled BOOLEAN DEFAULT TRUE, focus_lock_enabled BOOLEAN DEFAULT FALSE,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS user_tour_progress (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        completed BOOLEAN DEFAULT FALSE, steps_seen JSONB DEFAULT '[]',
        completed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS admin_exam_schedules (
        id SERIAL PRIMARY KEY, admin_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL, institution VARCHAR(255), department VARCHAR(100),
        program VARCHAR(255), year_level VARCHAR(10), semester VARCHAR(50),
        academic_year VARCHAR(20), exams JSONB DEFAULT '[]', file_url TEXT,
        is_published BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS admin_timetables (
        id SERIAL PRIMARY KEY, admin_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL, institution VARCHAR(255), department VARCHAR(100),
        program VARCHAR(255), year_level VARCHAR(10), semester VARCHAR(50),
        academic_year VARCHAR(20), timetable_type VARCHAR(30) DEFAULT 'weekly',
        entries JSONB DEFAULT '[]', is_published BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS phone_contacts (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        contact_phone VARCHAR(50) NOT NULL, contact_name VARCHAR(200),
        found_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, contact_phone)
      );
      CREATE TABLE IF NOT EXISTS peer_recommendations (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        recommended_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        score DECIMAL(5,4) DEFAULT 0, reasons JSONB DEFAULT '[]',
        is_dismissed BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, recommended_id)
      );
    `);
    res.json({ success: true, message: 'V4 migration complete' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
;

// ── PREFERENCES ──────────────────────────────────────────────────────────────
app.get('/api/preferences', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM user_preferences WHERE user_id=$1', [req.user.userId]);
    res.json({ success: true, preferences: rows[0] || null });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.put('/api/preferences', authMiddleware, async (req, res) => {
  const { studyStyle, noisePref, socialPref, studyHours, interests, academicGoals, courses, notificationsEnabled, focusLockEnabled } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO user_preferences(user_id,study_style,noise_pref,social_pref,study_hours,interests,academic_goals,courses,notifications_enabled,focus_lock_enabled,updated_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
       ON CONFLICT(user_id) DO UPDATE SET
         study_style=COALESCE($2,user_preferences.study_style), noise_pref=COALESCE($3,user_preferences.noise_pref),
         social_pref=COALESCE($4,user_preferences.social_pref), study_hours=COALESCE($5,user_preferences.study_hours),
         interests=COALESCE($6,user_preferences.interests), academic_goals=COALESCE($7,user_preferences.academic_goals),
         courses=COALESCE($8,user_preferences.courses), notifications_enabled=COALESCE($9,user_preferences.notifications_enabled),
         focus_lock_enabled=COALESCE($10,user_preferences.focus_lock_enabled), updated_at=NOW()
       RETURNING *`,
      [req.user.userId, studyStyle, noisePref, socialPref, studyHours,
       interests?JSON.stringify(interests):null, academicGoals?JSON.stringify(academicGoals):null,
       courses?JSON.stringify(courses):null, notificationsEnabled, focusLockEnabled]
    );
    res.json({ success: true, preferences: rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── TOUR ─────────────────────────────────────────────────────────────────────
app.get('/api/tour', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM user_tour_progress WHERE user_id=$1', [req.user.userId]);
    res.json({ success: true, tour: rows[0] || null });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/tour/step', authMiddleware, async (req, res) => {
  const { stepId } = req.body;
  try {
    await pool.query(
      `INSERT INTO user_tour_progress(user_id, steps_seen) VALUES($1,$2)
       ON CONFLICT(user_id) DO UPDATE SET steps_seen = user_tour_progress.steps_seen || $2::jsonb`,
      [req.user.userId, JSON.stringify([stepId])]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/tour/complete', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO user_tour_progress(user_id, completed, completed_at) VALUES($1, TRUE, NOW())
       ON CONFLICT(user_id) DO UPDATE SET completed=TRUE, completed_at=NOW()`,
      [req.user.userId]
    );
    await pool.query(`UPDATE users SET xp_points=xp_points+50 WHERE id=$1`, [req.user.userId]);
    await pool.query(
      `INSERT INTO activity_log(user_id,action_type,description,xp_delta) VALUES($1,'tour_complete','Completed platform tour',50)`,
      [req.user.userId]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── PHONE CONTACTS LOOKUP ────────────────────────────────────────────────────
app.post('/api/contacts/find', authMiddleware, async (req, res) => {
  const { phones } = req.body;
  if (!phones || !phones.length) return res.json({ success: true, found: [] });
  try {
    // Normalize phones: strip spaces and dashes
    const normalized = phones.map(p => p.replace(/[\s\-\(\)]/g, ''));
    // Find users by phone (try exact and partial matches)
    const result = await pool.query(
      `SELECT id, full_name, profile_image_url, department, institution, xp_points, level, phone,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=users.id) AS is_following
       FROM users
       WHERE phone = ANY($2) OR REPLACE(REPLACE(REPLACE(phone,' ',''),'-',''),'(','') = ANY($2)
       AND id != $1`,
      [req.user.userId, normalized]
    );
    // Save contacts
    for (const row of result.rows) {
      await pool.query(
        `INSERT INTO phone_contacts(user_id, contact_phone, contact_name, found_user_id)
         VALUES($1,$2,$3,$4) ON CONFLICT(user_id,contact_phone) DO UPDATE SET found_user_id=$4`,
        [req.user.userId, row.phone, row.full_name, row.id]
      ).catch(()=>{});
    }
    res.json({ success: true, found: result.rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── PEER RECOMMENDATIONS ─────────────────────────────────────────────────────
app.get('/api/recommendations/peers', authMiddleware, async (req, res) => {
  try {
    const meResult = await pool.query(
      'SELECT institution, department, year_of_study, study_style, social_pref, interests FROM users WHERE id=$1',
      [req.user.userId]
    );
    const me = meResult.rows[0];
    if (!me) return res.json({ success: true, peers: [] });

    // Algorithm: score by shared institution + dept + year + interests
    const result = await pool.query(
      `SELECT u.id, u.full_name, u.profile_image_url, u.department, u.institution,
              u.year_of_study, u.study_style, u.xp_points, u.level, u.bio,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=u.id) AS is_following,
              (CASE WHEN u.institution=$2 THEN 3 ELSE 0 END +
               CASE WHEN u.department=$3 THEN 3 ELSE 0 END +
               CASE WHEN u.year_of_study=$4 THEN 2 ELSE 0 END +
               CASE WHEN u.study_style=$5 THEN 1 ELSE 0 END) AS match_score
       FROM users u
       WHERE u.id != $1
         AND u.institution = $2
         AND u.onboarding_complete = TRUE
         AND u.id NOT IN (SELECT following_id FROM user_follows WHERE follower_id=$1)
       ORDER BY match_score DESC, u.xp_points DESC
       LIMIT 15`,
      [req.user.userId, me.institution, me.department, me.year_of_study, me.study_style]
    );
    res.json({ success: true, peers: result.rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── ADMIN EXAM SCHEDULES ──────────────────────────────────────────────────────
app.post('/api/admin/exam-schedules', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ success: false, message: 'Admin only' });
  const { title, institution, department, program, yearLevel, semester, academicYear, exams } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO admin_exam_schedules(admin_id,title,institution,department,program,year_level,semester,academic_year,exams,is_published)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE) RETURNING *`,
      [req.user.userId, title, institution, department, program, yearLevel, semester, academicYear, JSON.stringify(exams||[])]
    );
    // Push exams to matching users
    let updated = 0;
    if (exams && exams.length > 0) {
      const matchUsers = await pool.query(
        `SELECT id FROM users WHERE institution ILIKE $1 ${department?'AND department ILIKE $2':''}`,
        department ? [`%${institution}%`, `%${department}%`] : [`%${institution}%`]
      );
      for (const user of matchUsers.rows) {
        for (const exam of exams) {
          if (!exam.subject || !exam.date) continue;
          await pool.query(
            `INSERT INTO exams(user_id,title,subject,exam_date,location,duration_mins,notes)
             VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
            [user.id, exam.subject, exam.subject, exam.date+(exam.time?' '+exam.time:''),
             exam.location||'', parseInt(exam.duration)||120, `From admin schedule: ${title}`]
          ).catch(()=>{});
          updated++;
        }
      }
    }
    res.json({ success: true, schedule: rows[0], studentsUpdated: updated });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/admin/exam-schedules', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ success: false, message: 'Admin only' });
  try {
    const { rows } = await pool.query('SELECT * FROM admin_exam_schedules ORDER BY created_at DESC');
    res.json({ success: true, schedules: rows, uploads: rows.map(r => ({...r, type:'exam_schedule'})) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/admin/uploads', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ success: false, message: 'Admin only' });
  try {
    const [t, e] = await Promise.all([
      pool.query('SELECT *,\'timetable\' as type FROM admin_timetables ORDER BY created_at DESC'),
      pool.query('SELECT *,\'exam_schedule\' as type FROM admin_exam_schedules ORDER BY created_at DESC'),
    ]);
    res.json({ success: true, uploads: [...t.rows, ...e.rows].sort((a,b) => new Date(b.created_at)-new Date(a.created_at)) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── UNIVERSAL SEARCH ──────────────────────────────────────────────────────────
app.get('/api/search', authMiddleware, async (req, res) => {
  const { q, type } = req.query;
  if (!q || q.length < 2) return res.json({ success: true, results: {} });
  const term = `%${q}%`;
  try {
    const results = {};
    const include = (t) => !type || type === 'all' || type === t;

    if (include('people')) {
      const r = await pool.query(
        `SELECT id,full_name,profile_image_url,department,institution,xp_points,level FROM users
         WHERE (full_name ILIKE $1 OR student_id ILIKE $1 OR institution ILIKE $1) AND id!=$2 LIMIT 8`,
        [term, req.user.userId]
      );
      results.people = r.rows;
    }
    if (include('resources')) {
      const r = await pool.query(
        `SELECT id,title,subject,course_code,upvotes,file_type FROM library_resources
         WHERE (title ILIKE $1 OR subject ILIKE $1 OR course_code ILIKE $1) LIMIT 8`,
        [term]
      );
      results.resources = r.rows;
    }
    if (include('questions')) {
      const r = await pool.query(
        `SELECT hh.id,hh.title,hh.subject,hh.status,
                COUNT(hr.id) as response_count
         FROM homework_help hh
         LEFT JOIN homework_responses hr ON hr.help_request_id=hh.id
         WHERE hh.title ILIKE $1 OR hh.question ILIKE $1
         GROUP BY hh.id LIMIT 6`,
        [term]
      );
      results.questions = r.rows;
    }
    if (include('posts')) {
      const r = await pool.query(
        `SELECT cp.id,cp.content,cp.likes,u.full_name as author_name
         FROM campus_posts cp JOIN users u ON cp.author_id=u.id
         WHERE cp.content ILIKE $1 LIMIT 6`,
        [term]
      );
      results.posts = r.rows;
    }
    if (include('groups')) {
      const r = await pool.query(
        `SELECT id,name,subject,description FROM study_groups
         WHERE name ILIKE $1 OR subject ILIKE $1 OR description ILIKE $1 LIMIT 6`,
        [term]
      );
      results.groups = r.rows;
    }
    res.json({ success: true, results });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── MY EXAM SCHEDULE ──────────────────────────────────────────────────────────
app.get('/api/my-exam-schedule', authMiddleware, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT institution, department, year_of_study FROM users WHERE id=$1', [req.user.userId]);
    const user = userResult.rows[0];
    if (!user) return res.json({ success: true, schedules: [] });

    const { rows } = await pool.query(
      `SELECT * FROM admin_exam_schedules
       WHERE is_published = TRUE
         AND institution ILIKE $1
         ${user.department ? 'AND (department ILIKE $2 OR department IS NULL OR department = \'\')' : ''}
       ORDER BY created_at DESC LIMIT 5`,
      user.department ? [`%${user.institution}%`, `%${user.department}%`] : [`%${user.institution}%`]
    );
    res.json({ success: true, schedules: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── HOMEWORK RESPONSE UPVOTE ──────────────────────────────────────────────────
app.post('/api/homework-responses/:id/upvote', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE homework_responses SET upvotes=upvotes+1 WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/homework-help/:id/mark-answered', authMiddleware, async (req, res) => {
  try {
    await pool.query("UPDATE homework_help SET status='answered' WHERE id=$1 AND student_id=$2", [req.params.id, req.user.userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});



app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`💾 Storage: Supabase Storage`);
  console.log(`📊 Database: PostgreSQL (Supabase)`);
  console.log(`\n✅ Initialize database at: /api/init-db`);

  // ── Keep-alive ping (prevents Render free tier from spinning down) ──────────
  // Render spins down free services after 15 min of inactivity.
  // We ping our own /api/health every 14 minutes to stay awake.
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL || process.env.APP_URL;

  if (RENDER_URL) {
    const PING_INTERVAL_MS = 2 * 60 * 1000; // 2 minutes

    const pingKeepAlive = async () => {
      try {
        const res = await fetch(`${RENDER_URL}/api/health`);
        const data = await res.json();
        console.log(`[keep-alive] ping OK — ${new Date().toISOString()} — db: ${data.database}`);
      } catch (err) {
        console.warn(`[keep-alive] ping failed — ${err.message}`);
      }
    };

    // Kick off the first ping after 1 minute, then every 14 minutes
    setTimeout(() => {
      pingKeepAlive();
      setInterval(pingKeepAlive, PING_INTERVAL_MS);
    }, 60 * 1000);

    console.log(`💓 Keep-alive enabled — pinging ${RENDER_URL}/api/health every 2 min`);
  } else {
    console.log(`💤 Keep-alive disabled — set RENDER_EXTERNAL_URL env var to enable`);
  }
  
// ============================================================================
// CAMPUS PULSE — anonymous bulletin board
// ============================================================================

app.get('/api/campus-pulse', authMiddleware, async (req, res) => {
  const { category, sort = 'hot', limit = 50 } = req.query;
  try {
    let q = `
      SELECT p.*,
        (SELECT COUNT(*) FROM campus_pulse_comments c WHERE c.post_id = p.id) AS comment_count,
        (SELECT json_agg(json_build_object('emoji',emoji,'count',cnt)) FROM
          (SELECT emoji, COUNT(*) AS cnt FROM campus_pulse_reactions WHERE post_id=p.id GROUP BY emoji) r
        ) AS reactions
      FROM campus_pulse_posts p
      WHERE 1=1 `;
    const params = [];
    if (category && category !== 'all') { params.push(category); q += ` AND p.category = $${params.length}`; }
    if (sort === 'hot')  q += ` ORDER BY (p.likes * 2 + comment_count) DESC, p.created_at DESC`;
    else if (sort === 'new') q += ` ORDER BY p.created_at DESC`;
    else if (sort === 'top') q += ` ORDER BY p.likes DESC`;
    else q += ` ORDER BY p.created_at DESC`;
    params.push(parseInt(limit)); q += ` LIMIT $${params.length}`;
    const { rows } = await pool.query(q, params);
    res.json({ success: true, posts: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/campus-pulse', authMiddleware, async (req, res) => {
  const { category = 'general', text, isAnonymous = true, authorName } = req.body;
  if (!text?.trim()) return res.status(400).json({ success: false, message: 'Text required' });
  try {
    const uRes = await pool.query('SELECT full_name FROM users WHERE id=$1', [req.user.userId]);
    const name = isAnonymous ? 'Anonymous' : (authorName?.trim() || uRes.rows[0]?.full_name || 'Student');
    const { rows } = await pool.query(
      `INSERT INTO campus_pulse_posts (user_id, category, text, is_anonymous, author_name)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.userId, category, text.trim(), isAnonymous, name]
    );
    res.json({ success: true, post: { ...rows[0], comment_count: 0, reactions: null } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/campus-pulse/:id/like', authMiddleware, async (req, res) => {
  try {
    const { rows: existing } = await pool.query(
      `SELECT id FROM campus_pulse_reactions WHERE post_id=$1 AND user_id=$2 AND emoji='👍'`,
      [req.params.id, req.user.userId]
    );
    if (existing.length > 0) {
      await pool.query(`DELETE FROM campus_pulse_reactions WHERE id=$1`, [existing[0].id]);
      await pool.query(`UPDATE campus_pulse_posts SET likes=GREATEST(0,likes-1) WHERE id=$1`, [req.params.id]);
      return res.json({ success: true, action: 'unliked' });
    }
    await pool.query(`INSERT INTO campus_pulse_reactions(post_id,user_id,emoji) VALUES($1,$2,'👍')`, [req.params.id, req.user.userId]);
    await pool.query(`UPDATE campus_pulse_posts SET likes=likes+1 WHERE id=$1`, [req.params.id]);
    res.json({ success: true, action: 'liked' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/campus-pulse/:id/react', authMiddleware, async (req, res) => {
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ success: false, message: 'Emoji required' });
  try {
    await pool.query(
      `INSERT INTO campus_pulse_reactions(post_id,user_id,emoji) VALUES($1,$2,$3) ON CONFLICT(post_id,user_id,emoji) DO NOTHING`,
      [req.params.id, req.user.userId, emoji]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/campus-pulse/:id/comment', authMiddleware, async (req, res) => {
  const { text, isAnonymous = true, authorName } = req.body;
  if (!text?.trim()) return res.status(400).json({ success: false, message: 'Text required' });
  try {
    const uRes = await pool.query('SELECT full_name FROM users WHERE id=$1', [req.user.userId]);
    const name = isAnonymous ? 'Anonymous' : (authorName?.trim() || uRes.rows[0]?.full_name || 'Student');
    const { rows } = await pool.query(
      `INSERT INTO campus_pulse_comments(post_id,user_id,text,author_name) VALUES($1,$2,$3,$4) RETURNING *`,
      [req.params.id, req.user.userId, text.trim(), name]
    );
    res.json({ success: true, comment: rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/campus-pulse/:id/comments', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM campus_pulse_comments WHERE post_id=$1 ORDER BY created_at ASC`,
      [req.params.id]
    );
    res.json({ success: true, comments: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/api/campus-pulse/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM campus_pulse_posts WHERE id=$1 AND user_id=$2', [req.params.id, req.user.userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// GRADE TRACKER — subjects + grade entries
// ============================================================================

app.get('/api/grades/subjects', authMiddleware, async (req, res) => {
  try {
    const { rows: subjects } = await pool.query(
      `SELECT s.*, json_agg(json_build_object('id',g.id,'name',g.name,'pct',g.pct,'weight',g.weight,'logged_at',g.logged_at) ORDER BY g.logged_at) FILTER(WHERE g.id IS NOT NULL) AS grades
       FROM grade_subjects s LEFT JOIN grade_entries g ON g.subject_id=s.id
       WHERE s.user_id=$1 GROUP BY s.id ORDER BY s.created_at`,
      [req.user.userId]
    );
    res.json({ success: true, subjects: subjects.map(s => ({ ...s, grades: s.grades || [] })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/grades/subjects', authMiddleware, async (req, res) => {
  const { name, code, credits = 3, totalWeight = 100 } = req.body;
  if (!name?.trim()) return res.status(400).json({ success: false, message: 'Name required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO grade_subjects(user_id,name,code,credits,total_weight) VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.userId, name.trim(), code?.trim() || null, parseFloat(credits)||3, parseFloat(totalWeight)||100]
    );
    res.json({ success: true, subject: { ...rows[0], grades: [] } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.put('/api/grades/subjects/:id', authMiddleware, async (req, res) => {
  const { name, code, credits, totalWeight } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE grade_subjects SET name=$1, code=$2, credits=$3, total_weight=$4
       WHERE id=$5 AND user_id=$6 RETURNING *`,
      [name, code||null, parseFloat(credits)||3, parseFloat(totalWeight)||100, req.params.id, req.user.userId]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Not found' });
    res.json({ success: true, subject: rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/api/grades/subjects/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM grade_subjects WHERE id=$1 AND user_id=$2', [req.params.id, req.user.userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/grades/subjects/:id/entries', authMiddleware, async (req, res) => {
  const { name, pct, weight = 1 } = req.body;
  if (!name?.trim() || pct === undefined) return res.status(400).json({ success: false, message: 'name + pct required' });
  try {
    const { rows: owned } = await pool.query('SELECT id FROM grade_subjects WHERE id=$1 AND user_id=$2', [req.params.id, req.user.userId]);
    if (!owned.length) return res.status(403).json({ success: false, message: 'Not found' });
    const { rows } = await pool.query(
      `INSERT INTO grade_entries(subject_id,name,pct,weight) VALUES($1,$2,$3,$4) RETURNING *`,
      [req.params.id, name.trim(), parseFloat(pct), parseFloat(weight)||1]
    );
    res.json({ success: true, entry: rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/api/grades/subjects/:subjectId/entries/:entryId', authMiddleware, async (req, res) => {
  try {
    const { rows: owned } = await pool.query('SELECT id FROM grade_subjects WHERE id=$1 AND user_id=$2', [req.params.subjectId, req.user.userId]);
    if (!owned.length) return res.status(403).json({ success: false });
    await pool.query('DELETE FROM grade_entries WHERE id=$1 AND subject_id=$2', [req.params.entryId, req.params.subjectId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// STUDENTHUB — BACKEND ADDITIONS v2
// Drop this entire block into server.js JUST BEFORE the 404 handler.
// Also run POST /api/migrate-v2 once after deploy to apply the schema changes.
// ============================================================================

// ── Missing path import (required by uploadToSupabase) ───────────────────────
const path = require('path');

// ============================================================================
// MIGRATION — Run POST /api/migrate-v2 once to add all new tables + columns
// ============================================================================

const migrationSQL = `
-- Extend users table with XP / gamification fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS xp_points        INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS level            VARCHAR(20) DEFAULT 'Bronze';
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_streak     INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_date  DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS programme        VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS year_of_study    VARCHAR(10);
ALTER TABLE users ADD COLUMN IF NOT EXISTS subjects         TEXT[] DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS study_style      VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS study_times      TEXT[] DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS goals            TEXT[] DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarded_at     TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reputation_score INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS rank_percentile  DECIMAL(5,2) DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS store_views      INTEGER DEFAULT 0;

-- Extend library_resources with extra columns used in routes
ALTER TABLE library_resources ADD COLUMN IF NOT EXISTS category      VARCHAR(100) DEFAULT 'Lecture Notes';
ALTER TABLE library_resources ADD COLUMN IF NOT EXISTS thumbnail_url TEXT;

-- Extend study_groups with fields used in routes
ALTER TABLE study_groups ADD COLUMN IF NOT EXISTS program     VARCHAR(100);
ALTER TABLE study_groups ADD COLUMN IF NOT EXISTS study_mode  VARCHAR(50) DEFAULT 'social';
ALTER TABLE study_groups ADD COLUMN IF NOT EXISTS year_filter VARCHAR(10);

-- Extend notifications with sent tracking
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS sent     BOOLEAN DEFAULT false;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS sent_at  TIMESTAMP;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS read_at  TIMESTAMP;

-- Extend assignments with submitted_at
ALTER TABLE assignments ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMP;

-- Extend timetables with notification_minutes_before
ALTER TABLE timetables ADD COLUMN IF NOT EXISTS notification_minutes_before INTEGER DEFAULT 30;

-- Study sessions (for study groups)
CREATE TABLE IF NOT EXISTS study_sessions (
  id          SERIAL PRIMARY KEY,
  group_id    INTEGER REFERENCES study_groups(id) ON DELETE CASCADE,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  status      VARCHAR(20) DEFAULT 'active',
  started_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ended_at    TIMESTAMP,
  UNIQUE(group_id, user_id, status)
);

-- Session goals (for study groups)
CREATE TABLE IF NOT EXISTS session_goals (
  id           SERIAL PRIMARY KEY,
  group_id     INTEGER REFERENCES study_groups(id) ON DELETE CASCADE,
  created_by   INTEGER REFERENCES users(id) ON DELETE CASCADE,
  goal_text    TEXT NOT NULL,
  goal_date    DATE DEFAULT CURRENT_DATE,
  completed    BOOLEAN DEFAULT false,
  completed_by INTEGER REFERENCES users(id),
  completed_at TIMESTAMP,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Library comments
CREATE TABLE IF NOT EXISTS library_comments (
  id          SERIAL PRIMARY KEY,
  resource_id INTEGER REFERENCES library_resources(id) ON DELETE CASCADE,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  content     TEXT NOT NULL,
  parent_id   INTEGER REFERENCES library_comments(id) ON DELETE CASCADE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Library comment likes
CREATE TABLE IF NOT EXISTS library_comment_likes (
  id         SERIAL PRIMARY KEY,
  comment_id INTEGER REFERENCES library_comments(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(comment_id, user_id)
);

-- Stores table
CREATE TABLE IF NOT EXISTS stores (
  id           SERIAL PRIMARY KEY,
  user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
  owner_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  store_name   VARCHAR(255),
  slug         VARCHAR(100) UNIQUE,
  description  TEXT,
  banner_url   TEXT,
  category     VARCHAR(100),
  location     VARCHAR(255),
  phone        VARCHAR(50),
  email        VARCHAR(255),
  website      TEXT,
  rating       DECIMAL(3,2) DEFAULT 0,
  status       VARCHAR(20) DEFAULT 'active',
  store_views  INTEGER DEFAULT 0,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Store followers
CREATE TABLE IF NOT EXISTS store_followers (
  id         SERIAL PRIMARY KEY,
  store_id   INTEGER REFERENCES stores(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(store_id, user_id)
);

-- Seller followers (direct user follows for sellers)
CREATE TABLE IF NOT EXISTS seller_followers (
  id          SERIAL PRIMARY KEY,
  seller_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
  follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(seller_id, follower_id)
);

-- Store reviews
CREATE TABLE IF NOT EXISTS store_reviews (
  id          SERIAL PRIMARY KEY,
  store_id    INTEGER REFERENCES stores(id) ON DELETE CASCADE,
  reviewer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  rating      INTEGER CHECK (rating >= 1 AND rating <= 5),
  review_text TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(store_id, reviewer_id)
);

-- Classroom locations
CREATE TABLE IF NOT EXISTS classroom_locations (
  id            SERIAL PRIMARY KEY,
  user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
  building      VARCHAR(100),
  room_number   VARCHAR(50),
  location_name VARCHAR(255),
  location_lat  DECIMAL(10,8),
  location_lng  DECIMAL(11,8),
  notes         TEXT,
  is_public     BOOLEAN DEFAULT false,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, building, room_number)
);

-- ── NEW REWARD SYSTEM TABLES ──────────────────────────────────────────────

-- Badges catalogue
CREATE TABLE IF NOT EXISTS badges (
  id          SERIAL PRIMARY KEY,
  slug        VARCHAR(60) UNIQUE NOT NULL,
  name        VARCHAR(100) NOT NULL,
  description TEXT,
  icon        VARCHAR(10),
  tier        VARCHAR(20) DEFAULT 'bronze',
  xp_reward   INTEGER DEFAULT 0,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Badges earned by users
CREATE TABLE IF NOT EXISTS user_badges (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  badge_id   INTEGER REFERENCES badges(id) ON DELETE CASCADE,
  earned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, badge_id)
);

-- XP transaction ledger
CREATE TABLE IF NOT EXISTS point_transactions (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  action      VARCHAR(60) NOT NULL,
  points      INTEGER NOT NULL,
  reference   TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User follows (who follows whom)
CREATE TABLE IF NOT EXISTS user_follows (
  id          SERIAL PRIMARY KEY,
  follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(follower_id, following_id)
);

-- Direct messages
CREATE TABLE IF NOT EXISTS direct_messages (
  id          SERIAL PRIMARY KEY,
  sender_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  content     TEXT NOT NULL,
  is_read     BOOLEAN DEFAULT false,
  read_at     TIMESTAMP,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Event RSVPs
CREATE TABLE IF NOT EXISTS event_rsvps (
  id         SERIAL PRIMARY KEY,
  event_id   INTEGER REFERENCES school_events(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  status     VARCHAR(20) DEFAULT 'going',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(event_id, user_id)
);

-- Bounty fulfillments
CREATE TABLE IF NOT EXISTS bounty_fulfillments (
  id           SERIAL PRIMARY KEY,
  bounty_id    INTEGER REFERENCES library_bounties(id) ON DELETE CASCADE,
  fulfiller_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  resource_id  INTEGER REFERENCES library_resources(id) ON DELETE CASCADE,
  note         TEXT,
  accepted     BOOLEAN DEFAULT false,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Marketplace service images
ALTER TABLE marketplace_services ADD COLUMN IF NOT EXISTS images TEXT[] DEFAULT '{}';

-- Indexes for new tables
CREATE INDEX IF NOT EXISTS idx_point_tx_user    ON point_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_badges_user ON user_badges(user_id);
CREATE INDEX IF NOT EXISTS idx_dm_sender        ON direct_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_dm_receiver      ON direct_messages(receiver_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_fr  ON user_follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_fg  ON user_follows(following_id);
CREATE INDEX IF NOT EXISTS idx_event_rsvps      ON event_rsvps(event_id);
CREATE INDEX IF NOT EXISTS idx_session_goals    ON session_goals(group_id);
CREATE INDEX IF NOT EXISTS idx_study_sessions   ON study_sessions(group_id);
CREATE INDEX IF NOT EXISTS idx_library_comments ON library_comments(resource_id);
`;

app.post('/api/migrate-v2', async (req, res) => {
  try {
    const statements = migrationSQL
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);

    const results = [];
    for (const sql of statements) {
      try {
        await pool.query(sql);
        results.push({ ok: true, sql: sql.slice(0, 60) });
      } catch (err) {
        results.push({ ok: false, sql: sql.slice(0, 60), err: err.message });
      }
    }

    await seedBadges();
    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// REWARD SYSTEM — XP ACTIONS, LEVELS, HELPERS
// ============================================================================

const XP_ACTIONS = {
  resource_upload:      20,
  upvote_received:       5,
  homework_answered:    15,
  study_task_completed: 10,
  assignment_submitted:  5,
  daily_login:          10,
  class_joined:          3,
  study_group_created:  15,
  study_group_joined:    5,
  item_listed:          10,
  review_given:          5,
  library_upvote_given:  2,
  bounty_fulfilled:     30,
  login_streak_7:       50,
  login_streak_30:     200,
};

function calcLevel(xp) {
  if (xp >= 2000) return 'Diamond';
  if (xp >= 800)  return 'Platinum';
  if (xp >= 400)  return 'Gold';
  if (xp >= 150)  return 'Silver';
  return 'Bronze';
}

// Non-blocking — never delays a response
async function awardXP(userId, action, reference = null) {
  const points = XP_ACTIONS[action];
  if (!points) return;
  try {
    await pool.query(
      `INSERT INTO point_transactions (user_id, action, points, reference)
       VALUES ($1, $2, $3, $4)`,
      [userId, action, points, reference]
    );
    const result = await pool.query(
      `UPDATE users
       SET xp_points = xp_points + $1,
           level     = $2,
           updated_at = NOW()
       WHERE id = $3
       RETURNING xp_points`,
      [points, calcLevel((await pool.query('SELECT xp_points FROM users WHERE id=$1', [userId])).rows[0]?.xp_points + points || points), userId]
    );
    const newXp = result.rows[0]?.xp_points || 0;
    // Update level correctly after increment
    await pool.query(
      'UPDATE users SET level = $1 WHERE id = $2',
      [calcLevel(newXp), userId]
    );
    await checkBadges(userId);
  } catch (err) {
    console.error('[XP] award error:', err.message);
  }
}

async function checkBadges(userId) {
  try {
    const [uploads, answers, groups, reviews, streak, xp] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM library_resources WHERE uploader_id=$1', [userId]),
      pool.query('SELECT COUNT(*) FROM homework_responses WHERE responder_id=$1', [userId]),
      pool.query('SELECT COUNT(*) FROM study_group_members WHERE user_id=$1', [userId]),
      pool.query('SELECT COUNT(*) FROM reviews WHERE reviewer_id=$1', [userId]),
      pool.query('SELECT login_streak FROM users WHERE id=$1', [userId]),
      pool.query('SELECT xp_points FROM users WHERE id=$1', [userId]),
    ]);

    const u  = parseInt(uploads.rows[0].count);
    const a  = parseInt(answers.rows[0].count);
    const g  = parseInt(groups.rows[0].count);
    const rv = parseInt(reviews.rows[0].count);
    const ls = parseInt(streak.rows[0]?.login_streak || 0);
    const xpv = parseInt(xp.rows[0]?.xp_points || 0);

    const toAward = [];
    if (u >= 1)   toAward.push('first_upload');
    if (u >= 5)   toAward.push('bookworm');
    if (u >= 20)  toAward.push('scholar');
    if (a >= 1)   toAward.push('first_helper');
    if (a >= 10)  toAward.push('mentor');
    if (a >= 50)  toAward.push('sage');
    if (g >= 1)   toAward.push('study_buddy');
    if (g >= 5)   toAward.push('team_player');
    if (g >= 10)  toAward.push('social_butterfly');
    if (rv >= 1)  toAward.push('reviewer');
    if (ls >= 7)  toAward.push('streak_7');
    if (ls >= 30) toAward.push('streak_30');
    if (xpv >= 500)  toAward.push('rising_star');
    if (xpv >= 2000) toAward.push('legend');

    for (const slug of toAward) {
      const badge = await pool.query('SELECT id FROM badges WHERE slug=$1', [slug]);
      if (!badge.rows.length) continue;
      const badgeId = badge.rows[0].id;
      const already = await pool.query(
        'SELECT id FROM user_badges WHERE user_id=$1 AND badge_id=$2',
        [userId, badgeId]
      );
      if (!already.rows.length) {
        await pool.query(
          'INSERT INTO user_badges (user_id, badge_id) VALUES ($1,$2)',
          [userId, badgeId]
        );
        // Notify
        await pool.query(
          `INSERT INTO notifications (user_id, notification_type, title, message, scheduled_time)
           VALUES ($1, 'badge', $2, $3, NOW())`,
          [userId, `Badge Unlocked!`,
           `You earned the "${slug.replace(/_/g,' ')}" badge. Keep it up.`]
        );
      }
    }
  } catch (err) {
    console.error('[Badge] check error:', err.message);
  }
}

async function seedBadges() {
  const badges = [
    { slug: 'first_upload',      name: 'First Upload',        icon: '📄', tier: 'bronze',   xp: 10,  desc: 'Uploaded your first resource.' },
    { slug: 'bookworm',          name: 'Bookworm',             icon: '📚', tier: 'silver',   xp: 25,  desc: 'Uploaded 5 resources.' },
    { slug: 'scholar',           name: 'Scholar',              icon: '🎓', tier: 'gold',     xp: 75,  desc: 'Uploaded 20 resources.' },
    { slug: 'first_helper',      name: 'First Helper',         icon: '🙋', tier: 'bronze',   xp: 15,  desc: 'Answered a homework question.' },
    { slug: 'mentor',            name: 'Mentor',               icon: '🧑‍🏫', tier: 'silver', xp: 40,  desc: 'Answered 10 homework questions.' },
    { slug: 'sage',              name: 'Sage',                 icon: '🦉', tier: 'platinum', xp: 150, desc: 'Answered 50 homework questions.' },
    { slug: 'study_buddy',       name: 'Study Buddy',          icon: '🤝', tier: 'bronze',   xp: 10,  desc: 'Joined your first study group.' },
    { slug: 'team_player',       name: 'Team Player',          icon: '🏆', tier: 'silver',   xp: 30,  desc: 'Joined 5 study groups.' },
    { slug: 'social_butterfly',  name: 'Social Butterfly',     icon: '🦋', tier: 'gold',     xp: 75,  desc: 'Active in 10+ study groups.' },
    { slug: 'marketplace_debut', name: 'Marketplace Debut',    icon: '🛍️', tier: 'bronze',   xp: 15,  desc: 'Listed your first item.' },
    { slug: 'top_seller',        name: 'Top Seller',           icon: '💎', tier: 'gold',     xp: 100, desc: 'Listed 20+ items.' },
    { slug: 'streak_7',          name: '7-Day Streak',         icon: '🔥', tier: 'silver',   xp: 50,  desc: 'Logged in 7 days in a row.' },
    { slug: 'streak_30',         name: 'Monthly Grind',        icon: '⚡', tier: 'platinum', xp: 200, desc: 'Logged in 30 days in a row.' },
    { slug: 'reviewer',          name: 'Reviewer',             icon: '⭐', tier: 'bronze',   xp: 10,  desc: 'Left your first review.' },
    { slug: 'rising_star',       name: 'Rising Star',          icon: '🌟', tier: 'gold',     xp: 50,  desc: 'Reached 500 XP.' },
    { slug: 'legend',            name: 'Legend',               icon: '👑', tier: 'diamond',  xp: 300, desc: 'Reached 2000 XP.' },
  ];

  for (const b of badges) {
    await pool.query(
      `INSERT INTO badges (slug, name, description, icon, tier, xp_reward)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (slug) DO UPDATE
         SET name=$2, description=$3, icon=$4, tier=$5, xp_reward=$6`,
      [b.slug, b.name, b.desc, b.icon, b.tier, b.xp]
    );
  }
}

// ============================================================================
// REWARDS ROUTES
// ============================================================================

// GET /api/rewards/me — own XP summary
app.get('/api/rewards/me', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.userId;
    const user = await pool.query(
      `SELECT id, full_name, xp_points, level, login_streak, reputation_score, rank_percentile
       FROM users WHERE id=$1`,
      [uid]
    );
    if (!user.rows.length) return res.status(404).json({ success: false, message: 'Not found' });

    const badges = await pool.query(
      `SELECT b.slug, b.name, b.icon, b.tier, b.description, ub.earned_at
       FROM user_badges ub
       JOIN badges b ON b.id = ub.badge_id
       WHERE ub.user_id=$1
       ORDER BY ub.earned_at DESC`,
      [uid]
    );

    const history = await pool.query(
      `SELECT action, points, reference, created_at
       FROM point_transactions
       WHERE user_id=$1
       ORDER BY created_at DESC
       LIMIT 30`,
      [uid]
    );

    const rank = await pool.query(
      `SELECT COUNT(*)+1 AS rank FROM users WHERE xp_points > (SELECT xp_points FROM users WHERE id=$1)`,
      [uid]
    );

    res.json({
      success: true,
      rewards: {
        ...user.rows[0],
        badges: badges.rows,
        recentHistory: history.rows,
        globalRank: parseInt(rank.rows[0].rank),
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/rewards/leaderboard?institution=&limit=20
app.get('/api/rewards/leaderboard', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const institution = req.query.institution;

    const params = institution ? [institution, limit] : [limit];
    const where  = institution ? 'WHERE institution=$1' : '';
    const lParam = institution ? '$2' : '$1';

    const result = await pool.query(
      `SELECT id, full_name, institution, profile_image_url, xp_points, level, login_streak,
              ROW_NUMBER() OVER (ORDER BY xp_points DESC) AS rank
       FROM users
       ${where}
       ORDER BY xp_points DESC
       LIMIT ${lParam}`,
      params
    );

    // Highlight current user's position
    const myRank = await pool.query(
      `SELECT COUNT(*)+1 AS rank FROM users WHERE xp_points > (SELECT xp_points FROM users WHERE id=$1)`,
      [req.user.userId]
    );

    res.json({
      success: true,
      leaderboard: result.rows,
      myRank: parseInt(myRank.rows[0].rank),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/rewards/badges — all badges + which ones you have
app.get('/api/rewards/badges', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*,
              CASE WHEN ub.id IS NOT NULL THEN true ELSE false END AS earned,
              ub.earned_at
       FROM badges b
       LEFT JOIN user_badges ub ON ub.badge_id = b.id AND ub.user_id=$1
       ORDER BY b.tier DESC, b.xp_reward DESC`,
      [req.user.userId]
    );
    res.json({ success: true, badges: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/rewards/history?limit=50
app.get('/api/rewards/history', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const result = await pool.query(
      `SELECT action, points, reference, created_at
       FROM point_transactions
       WHERE user_id=$1
       ORDER BY created_at DESC
       LIMIT $2`,
      [req.user.userId, limit]
    );
    res.json({ success: true, history: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// DASHBOARD STATS
// ============================================================================

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.userId;
    const [user, uploads, groups, assignments, exams, unread, upcoming] = await Promise.all([
      pool.query(
        `SELECT xp_points, level, login_streak, reputation_score FROM users WHERE id=$1`,
        [uid]
      ),
      pool.query('SELECT COUNT(*) FROM library_resources WHERE uploader_id=$1', [uid]),
      pool.query('SELECT COUNT(*) FROM study_group_members WHERE user_id=$1', [uid]),
      pool.query(
        `SELECT COUNT(*) FROM assignments WHERE user_id=$1 AND status='pending' AND due_date > NOW()`,
        [uid]
      ),
      pool.query(
        `SELECT COUNT(*) FROM exam_schedules WHERE user_id=$1 AND exam_date > NOW()`,
        [uid]
      ),
      pool.query(
        `SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read=false AND scheduled_time<=NOW()`,
        [uid]
      ),
      pool.query(
        `SELECT title, due_date FROM assignments
         WHERE user_id=$1 AND status='pending' AND due_date > NOW()
         ORDER BY due_date ASC LIMIT 5`,
        [uid]
      ),
    ]);

    const rank = await pool.query(
      `SELECT COUNT(*)+1 AS rank FROM users WHERE xp_points > (SELECT xp_points FROM users WHERE id=$1)`,
      [uid]
    );

    res.json({
      success: true,
      stats: {
        xp:              parseInt(user.rows[0]?.xp_points || 0),
        level:           user.rows[0]?.level || 'Bronze',
        loginStreak:     parseInt(user.rows[0]?.login_streak || 0),
        reputation:      parseInt(user.rows[0]?.reputation_score || 0),
        globalRank:      parseInt(rank.rows[0].rank),
        uploads:         parseInt(uploads.rows[0].count),
        studyGroups:     parseInt(groups.rows[0].count),
        pendingAssignments: parseInt(assignments.rows[0].count),
        upcomingExams:   parseInt(exams.rows[0].count),
        unreadNotifications: parseInt(unread.rows[0].count),
        upcomingDeadlines: upcoming.rows,
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// USER SEARCH + PROFILES + FOLLOWS
// ============================================================================

// GET /api/users/search?q=&institution=
app.get('/api/users/search', authMiddleware, async (req, res) => {
  const { q, institution } = req.query;
  if (!q || q.length < 2) {
    return res.status(400).json({ success: false, message: 'Search query too short' });
  }
  try {
    const term = `%${q}%`;
    const params = institution
      ? [term, term, term, institution, req.user.userId]
      : [term, term, term, req.user.userId];
    const institutionClause = institution ? 'AND u.institution=$4' : '';
    const uidParam = institution ? '$5' : '$4';

    const result = await pool.query(
      `SELECT u.id, u.full_name, u.student_id, u.institution, u.profile_image_url,
              u.xp_points, u.level, u.bio,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=${uidParam} AND following_id=u.id) AS is_following
       FROM users u
       WHERE (u.full_name ILIKE $1 OR u.student_id ILIKE $2 OR u.institution ILIKE $3)
       ${institutionClause}
       AND u.id != ${uidParam}
       ORDER BY u.xp_points DESC
       LIMIT 30`,
      params
    );
    res.json({ success: true, users: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/users/:id/profile — public profile
app.get('/api/users/:id/profile', authMiddleware, async (req, res) => {
  const { id } = req.params;
  if (isNaN(id)) return res.status(400).json({ success: false, message: 'Invalid ID' });
  try {
    const user = await pool.query(
      `SELECT u.id, u.full_name, u.institution, u.profile_image_url, u.bio,
              u.xp_points, u.level, u.login_streak, u.reputation_score,
              u.created_at,
              (SELECT COUNT(*) FROM library_resources WHERE uploader_id=u.id) AS uploads,
              (SELECT COUNT(*) FROM study_group_members WHERE user_id=u.id) AS groups_joined,
              (SELECT COUNT(*) FROM user_follows WHERE following_id=u.id) AS followers,
              (SELECT COUNT(*) FROM user_follows WHERE follower_id=u.id) AS following,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$2 AND following_id=u.id) AS is_following
       FROM users u WHERE u.id=$1`,
      [id, req.user.userId]
    );
    if (!user.rows.length) return res.status(404).json({ success: false, message: 'User not found' });

    const badges = await pool.query(
      `SELECT b.slug, b.name, b.icon, b.tier FROM user_badges ub
       JOIN badges b ON b.id=ub.badge_id WHERE ub.user_id=$1 ORDER BY ub.earned_at DESC LIMIT 6`,
      [id]
    );

    const recentUploads = await pool.query(
      `SELECT id, title, subject, created_at FROM library_resources
       WHERE uploader_id=$1 AND is_public=true ORDER BY created_at DESC LIMIT 5`,
      [id]
    );

    res.json({
      success: true,
      profile: user.rows[0],
      badges: badges.rows,
      recentUploads: recentUploads.rows,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/users/:id/follow — toggle follow
app.post('/api/users/:id/follow', authMiddleware, async (req, res) => {
  const targetId = parseInt(req.params.id);
  const uid = req.user.userId;
  if (isNaN(targetId)) return res.status(400).json({ success: false, message: 'Invalid ID' });
  if (targetId === uid) return res.status(400).json({ success: false, message: 'Cannot follow yourself' });
  try {
    const existing = await pool.query(
      'SELECT id FROM user_follows WHERE follower_id=$1 AND following_id=$2',
      [uid, targetId]
    );
    if (existing.rows.length) {
      await pool.query('DELETE FROM user_follows WHERE follower_id=$1 AND following_id=$2', [uid, targetId]);
      return res.json({ success: true, following: false });
    }
    await pool.query(
      'INSERT INTO user_follows (follower_id, following_id) VALUES ($1,$2)',
      [uid, targetId]
    );
    res.json({ success: true, following: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/users/me/followers
app.get('/api/users/me/followers', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.full_name, u.profile_image_url, u.institution, u.level, uf.created_at
       FROM user_follows uf
       JOIN users u ON u.id = uf.follower_id
       WHERE uf.following_id=$1
       ORDER BY uf.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, followers: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/users/me/following
app.get('/api/users/me/following', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.full_name, u.profile_image_url, u.institution, u.level, uf.created_at
       FROM user_follows uf
       JOIN users u ON u.id = uf.following_id
       WHERE uf.follower_id=$1
       ORDER BY uf.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, following: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// DIRECT MESSAGES
// ============================================================================

// GET /api/messages/inbox — list of conversations
app.get('/api/messages/inbox', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.userId;
    const result = await pool.query(
      `SELECT DISTINCT ON (other_id)
         other_id,
         other_name,
         other_image,
         content AS last_message,
         created_at AS last_at,
         unread_count
       FROM (
         SELECT
           CASE WHEN dm.sender_id=$1 THEN dm.receiver_id ELSE dm.sender_id END AS other_id,
           CASE WHEN dm.sender_id=$1 THEN ru.full_name    ELSE su.full_name   END AS other_name,
           CASE WHEN dm.sender_id=$1 THEN ru.profile_image_url ELSE su.profile_image_url END AS other_image,
           dm.content,
           dm.created_at,
           (SELECT COUNT(*) FROM direct_messages
            WHERE sender_id=(CASE WHEN dm.sender_id=$1 THEN dm.receiver_id ELSE dm.sender_id END)
              AND receiver_id=$1 AND is_read=false) AS unread_count
         FROM direct_messages dm
         JOIN users su ON su.id = dm.sender_id
         JOIN users ru ON ru.id = dm.receiver_id
         WHERE dm.sender_id=$1 OR dm.receiver_id=$1
         ORDER BY dm.created_at DESC
       ) t
       ORDER BY other_id, last_at DESC`,
      [uid]
    );
    res.json({ success: true, conversations: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/messages/:userId — thread with a specific user
app.get('/api/messages/:userId', authMiddleware, async (req, res) => {
  const other = parseInt(req.params.userId);
  const uid = req.user.userId;
  if (isNaN(other)) return res.status(400).json({ success: false, message: 'Invalid user ID' });
  try {
    // Mark received messages as read
    await pool.query(
      `UPDATE direct_messages SET is_read=true, read_at=NOW()
       WHERE sender_id=$1 AND receiver_id=$2 AND is_read=false`,
      [other, uid]
    );
    const messages = await pool.query(
      `SELECT dm.*, u.full_name AS sender_name, u.profile_image_url AS sender_image
       FROM direct_messages dm
       JOIN users u ON u.id = dm.sender_id
       WHERE (dm.sender_id=$1 AND dm.receiver_id=$2)
          OR (dm.sender_id=$2 AND dm.receiver_id=$1)
       ORDER BY dm.created_at ASC
       LIMIT 200`,
      [uid, other]
    );
    // Get other user's info
    const otherUser = await pool.query(
      'SELECT id, full_name, profile_image_url, institution FROM users WHERE id=$1',
      [other]
    );
    res.json({ success: true, messages: messages.rows, user: otherUser.rows[0] || null });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/messages — send a DM
app.post('/api/messages', authMiddleware, async (req, res) => {
  const { receiverId, content } = req.body;
  const uid = req.user.userId;
  if (!receiverId || !content?.trim()) {
    return res.status(400).json({ success: false, message: 'Receiver and content required' });
  }
  if (parseInt(receiverId) === uid) {
    return res.status(400).json({ success: false, message: 'Cannot message yourself' });
  }
  try {
    const receiver = await pool.query('SELECT id FROM users WHERE id=$1', [receiverId]);
    if (!receiver.rows.length) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const result = await pool.query(
      `INSERT INTO direct_messages (sender_id, receiver_id, content)
       VALUES ($1,$2,$3) RETURNING *`,
      [uid, receiverId, content.trim()]
    );
    // Deliver a notification to receiver
    await pool.query(
      `INSERT INTO notifications (user_id, notification_type, reference_id, title, message, scheduled_time)
       VALUES ($1,'message',$2,$3,$4,NOW())`,
      [receiverId, uid, 'New Message',
       (await pool.query('SELECT full_name FROM users WHERE id=$1',[uid])).rows[0]?.full_name + ' sent you a message']
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/messages/:id — delete own message
app.delete('/api/messages/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM direct_messages WHERE id=$1 AND sender_id=$2 RETURNING id',
      [req.params.id, req.user.userId]
    );
    if (!result.rowCount) return res.status(403).json({ success: false, message: 'Not found or unauthorized' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// LIBRARY BOUNTIES (FULL IMPLEMENTATION)
// ============================================================================

// GET /api/library/bounties
app.get('/api/library/bounties', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lb.*, u.full_name AS requester_name, u.profile_image_url AS requester_image,
              (SELECT COUNT(*) FROM bounty_fulfillments WHERE bounty_id=lb.id) AS fulfillment_count
       FROM library_bounties lb
       JOIN users u ON u.id = lb.requester_id
       WHERE lb.status='open'
       ORDER BY lb.reward_points DESC, lb.created_at DESC`,
    );
    res.json({ success: true, bounties: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/library/bounties — create a bounty request
app.post('/api/library/bounties', authMiddleware, async (req, res) => {
  const { courseCode, description, rewardPoints } = req.body;
  if (!courseCode) return res.status(400).json({ success: false, message: 'Course code required' });
  try {
    const result = await pool.query(
      `INSERT INTO library_bounties (requester_id, course_code, description, reward_points)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [req.user.userId, courseCode.toUpperCase().trim(), description || '', rewardPoints || 0]
    );
    res.json({ success: true, bounty: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/library/bounties/:id/fulfill — fulfill a bounty
app.post('/api/library/bounties/:id/fulfill', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  const bountyId = parseInt(req.params.id);
  const { resourceId, note } = req.body;
  if (!resourceId) return res.status(400).json({ success: false, message: 'Resource ID required' });
  try {
    const bounty = await pool.query('SELECT * FROM library_bounties WHERE id=$1', [bountyId]);
    if (!bounty.rows.length) return res.status(404).json({ success: false, message: 'Bounty not found' });
    if (bounty.rows[0].status !== 'open') {
      return res.status(400).json({ success: false, message: 'Bounty is already closed' });
    }
    if (bounty.rows[0].requester_id === uid) {
      return res.status(400).json({ success: false, message: 'Cannot fulfill your own bounty' });
    }
    // Check resource belongs to fulfiller
    const res2 = await pool.query(
      'SELECT id FROM library_resources WHERE id=$1 AND uploader_id=$2',
      [resourceId, uid]
    );
    if (!res2.rows.length) {
      return res.status(403).json({ success: false, message: 'You must own the resource to fulfill a bounty' });
    }
    // Insert fulfillment
    const fulfillment = await pool.query(
      `INSERT INTO bounty_fulfillments (bounty_id, fulfiller_id, resource_id, note)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [bountyId, uid, resourceId, note || '']
    );
    // Close the bounty
    await pool.query('UPDATE library_bounties SET status=$1 WHERE id=$2', ['fulfilled', bountyId]);
    // Award XP for bounty fulfillment
    setImmediate(() => awardXP(uid, 'bounty_fulfilled', `bounty:${bountyId}`));
    // Notify requester
    await pool.query(
      `INSERT INTO notifications (user_id, notification_type, reference_id, title, message, scheduled_time)
       VALUES ($1,'bounty',$2,'Bounty Fulfilled',$3,NOW())`,
      [bounty.rows[0].requester_id, bountyId,
       `Someone uploaded a resource for your ${bounty.rows[0].course_code} bounty.`]
    );
    res.json({ success: true, fulfillment: fulfillment.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/library/bounties/:id — requester cancels
app.delete('/api/library/bounties/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM library_bounties WHERE id=$1 AND requester_id=$2 RETURNING id`,
      [req.params.id, req.user.userId]
    );
    if (!result.rowCount) return res.status(403).json({ success: false, message: 'Not found or unauthorized' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// EVENT RSVPs
// ============================================================================

// POST /api/school-events/:id/rsvp — going / maybe / not_going
app.post('/api/school-events/:id/rsvp', authMiddleware, async (req, res) => {
  const { status } = req.body;
  const validStatuses = ['going', 'maybe', 'not_going'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid RSVP status' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO event_rsvps (event_id, user_id, status)
       VALUES ($1,$2,$3)
       ON CONFLICT (event_id, user_id) DO UPDATE SET status=$3
       RETURNING *`,
      [req.params.id, req.user.userId, status]
    );
    // Count updated attendance
    const counts = await pool.query(
      `SELECT status, COUNT(*) FROM event_rsvps WHERE event_id=$1 GROUP BY status`,
      [req.params.id]
    );
    res.json({ success: true, rsvp: result.rows[0], counts: counts.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/school-events/:id/rsvps
app.get('/api/school-events/:id/rsvps', authMiddleware, async (req, res) => {
  try {
    const counts = await pool.query(
      `SELECT status, COUNT(*) FROM event_rsvps WHERE event_id=$1 GROUP BY status`,
      [req.params.id]
    );
    const myRsvp = await pool.query(
      `SELECT status FROM event_rsvps WHERE event_id=$1 AND user_id=$2`,
      [req.params.id, req.user.userId]
    );
    res.json({
      success: true,
      counts: counts.rows,
      myStatus: myRsvp.rows[0]?.status || null,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// NOTIFICATIONS — read-all
// ============================================================================

app.post('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `UPDATE notifications SET read=true, read_at=NOW()
       WHERE user_id=$1 AND read=false`,
      [req.user.userId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/notifications/:id
app.delete('/api/notifications/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM notifications WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.userId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// MARKETPLACE — MISSING / ENHANCED ROUTES
// ============================================================================

// GET /api/marketplace/services/:id
app.get('/api/marketplace/services/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE marketplace_services SET views=views+1 WHERE id=$1', [req.params.id]);
    const result = await pool.query(
      `SELECT ms.*, u.full_name AS provider_name, u.phone AS provider_phone,
              u.profile_image_url AS provider_image,
              (SELECT AVG(rating)::numeric(10,1) FROM reviews WHERE reviewed_user_id=ms.provider_id) AS provider_rating,
              (SELECT COUNT(*) FROM reviews WHERE reviewed_user_id=ms.provider_id) AS provider_review_count
       FROM marketplace_services ms
       JOIN users u ON u.id=ms.provider_id
       WHERE ms.id=$1`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Service not found' });
    res.json({ success: true, service: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PUT /api/marketplace/services/:id
app.put('/api/marketplace/services/:id', authMiddleware, async (req, res) => {
  const { title, description, price, category, serviceCategory, duration, availability } = req.body;
  try {
    const check = await pool.query('SELECT provider_id FROM marketplace_services WHERE id=$1', [req.params.id]);
    if (!check.rows.length) return res.status(404).json({ success: false, message: 'Not found' });
    if (check.rows[0].provider_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    const result = await pool.query(
      `UPDATE marketplace_services
       SET title=$1, description=$2, price=$3, category=$4,
           service_category=$5, duration=$6, availability=$7
       WHERE id=$8 RETURNING *`,
      [title, description, price, category, serviceCategory || 'general', duration, availability, req.params.id]
    );
    res.json({ success: true, service: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/marketplace/services/:id/images — upload images for a service
app.post('/api/marketplace/services/:id/images', authMiddleware, imageUpload.array('images', 5), async (req, res) => {
  try {
    const check = await pool.query('SELECT provider_id FROM marketplace_services WHERE id=$1', [req.params.id]);
    if (!check.rows.length) return res.status(404).json({ success: false, message: 'Not found' });
    if (check.rows[0].provider_id !== req.user.userId) return res.status(403).json({ success: false, message: 'Unauthorized' });
    const urls = [];
    for (const file of (req.files || [])) {
      urls.push(await uploadToSupabase(file, 'marketplace-images', 'services/'));
    }
    await pool.query(
      `UPDATE marketplace_services SET images=array_cat(images, $1::text[]) WHERE id=$2`,
      [urls, req.params.id]
    );
    res.json({ success: true, urls });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/marketplace/my-listings — current user's goods + services
app.get('/api/marketplace/my-listings', authMiddleware, async (req, res) => {
  try {
    const [goods, services] = await Promise.all([
      pool.query(
        'SELECT * FROM marketplace_goods WHERE seller_id=$1 ORDER BY created_at DESC',
        [req.user.userId]
      ),
      pool.query(
        'SELECT * FROM marketplace_services WHERE provider_id=$1 ORDER BY created_at DESC',
        [req.user.userId]
      ),
    ]);
    res.json({ success: true, goods: goods.rows, services: services.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// UPDATED AUTH ROUTES — Login with streak + XP, Profile with XP fields
// These REPLACE the originals that are earlier in the file.
// Express uses the LAST matching route, so placing these here overrides them.
// ============================================================================

// OVERRIDE: POST /api/auth/login — adds streak tracking + daily login XP
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (!result.rows.length) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Streak logic
    const today = new Date().toISOString().slice(0, 10);
    const lastLogin = user.last_login_date ? user.last_login_date.toISOString().slice(0, 10) : null;
    let newStreak = user.login_streak || 0;
    let awardedStreak = false;

    if (lastLogin !== today) {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yday = yesterday.toISOString().slice(0, 10);
      newStreak = lastLogin === yday ? newStreak + 1 : 1;
      await pool.query(
        'UPDATE users SET login_streak=$1, last_login_date=$2 WHERE id=$3',
        [newStreak, today, user.id]
      );
      awardedStreak = true;
      setImmediate(async () => {
        await awardXP(user.id, 'daily_login');
        if (newStreak === 7)  await awardXP(user.id, 'login_streak_7',  'streak:7');
        if (newStreak === 30) await awardXP(user.id, 'login_streak_30', 'streak:30');
      });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'fallback-change-this',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id:              user.id,
        email:           user.email,
        fullName:        user.full_name,
        studentId:       user.student_id,
        institution:     user.institution,
        phone:           user.phone,
        bio:             user.bio,
        isCourseRep:     user.is_course_rep,
        profileImageUrl: user.profile_image_url,
        xpPoints:        user.xp_points || 0,
        level:           user.level || 'Bronze',
        loginStreak:     newStreak,
        onboarded:       !!user.onboarded_at,
        programme:       user.programme,
        yearOfStudy:     user.year_of_study,
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: GET /api/auth/profile — includes XP fields
app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, full_name, student_id, institution, phone, bio,
              profile_image_url, is_course_rep, xp_points, level,
              login_streak, reputation_score, rank_percentile, onboarded_at,
              programme, year_of_study, subjects, study_style, study_times, goals
       FROM users WHERE id=$1`,
      [req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// XP HOOKS — Wrapper routes that award XP on key actions
// These are new routes placed AFTER the originals for the actions below.
// Because some originals already handle the logic, we wrap via middleware.
// ============================================================================

// OVERRIDE: POST /api/library — award XP for resource upload
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
    const fileUrl = await uploadToSupabase(mainFile, 'library-resources', 'documents/');
    let thumbnailUrl = null;
    if (thumbnailFile) {
      thumbnailUrl = await uploadToSupabase(thumbnailFile, 'library-resources', 'thumbnails/');
    }
    const result = await pool.query(
      `INSERT INTO library_resources
       (uploader_id, title, description, subject, category, file_url, thumbnail_url, file_type, file_size)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.userId, title, description, subject,
       category || 'Lecture Notes', fileUrl, thumbnailUrl,
       mainFile.mimetype, mainFile.size]
    );
    setImmediate(() => {
      awardXP(req.user.userId, 'resource_upload', `resource:${result.rows[0].id}`);
      updateStudentRank(req.user.userId);
    });
    res.json({ success: true, resource: result.rows[0] });
  } catch (err) {
    console.error('Library upload error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/homework-help/:id/respond — award XP for answering
app.post('/api/homework-help/:id/respond', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { response } = req.body;
  if (!response?.trim()) return res.status(400).json({ success: false, message: 'Response required' });
  try {
    const result = await pool.query(
      'INSERT INTO homework_responses (help_request_id, responder_id, response) VALUES ($1,$2,$3) RETURNING *',
      [id, req.user.userId, response.trim()]
    );
    await pool.query(
      "UPDATE homework_help SET status='answered' WHERE id=$1 AND status='open'",
      [id]
    );
    // Notify question asker
    const question = await pool.query('SELECT student_id, title FROM homework_help WHERE id=$1', [id]);
    if (question.rows.length) {
      await pool.query(
        `INSERT INTO notifications (user_id, notification_type, reference_id, title, message, scheduled_time)
         VALUES ($1,'homework',$2,'New Answer',$3,NOW())`,
        [question.rows[0].student_id, parseInt(id),
         `Someone answered your question: "${question.rows[0].title}"`]
      );
    }
    setImmediate(() => awardXP(req.user.userId, 'homework_answered', `help:${id}`));
    res.json({ success: true, response: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/study-groups — award XP for creating
app.post('/api/study-groups', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  const { name, description, subject, program, maxMembers, isPrivate, study_mode, year_filter } = req.body;
  if (!name) return res.status(400).json({ success: false, message: 'Group name required' });
  try {
    const result = await pool.query(
      `INSERT INTO study_groups
         (creator_id, name, description, subject, program, max_members, is_private, study_mode, year_filter)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [uid, name, description||null, subject||null, program||null,
       maxMembers||50, isPrivate||false, study_mode||'social', year_filter||null]
    );
    const group = result.rows[0];
    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id, role) VALUES ($1,$2,$3)',
      [group.id, uid, 'admin']
    );
    setImmediate(() => awardXP(uid, 'study_group_created', `group:${group.id}`));
    res.json({ success: true, group });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/class-spaces/:id/join — award XP for joining
app.post('/api/class-spaces/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const classExists = await pool.query('SELECT id FROM class_spaces WHERE id=$1', [id]);
    if (!classExists.rows.length) {
      return res.status(404).json({ success: false, message: 'Class not found' });
    }
    const existing = await pool.query(
      'SELECT id FROM class_space_members WHERE class_space_id=$1 AND user_id=$2',
      [id, req.user.userId]
    );
    const alreadyMember = existing.rows.length > 0;
    await pool.query(
      'INSERT INTO class_space_members (class_space_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [id, req.user.userId]
    );
    if (!alreadyMember) {
      setImmediate(() => awardXP(req.user.userId, 'class_joined', `class:${id}`));
    }
    res.json({ success: true, message: 'Joined class space' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/marketplace/goods — award XP for listing
app.post('/api/marketplace/goods', authMiddleware, imageUpload.array('images', 5), async (req, res) => {
  const { title, description, price, category, condition, location } = req.body;
  try {
    const imageUrls = [];
    for (const file of (req.files || [])) {
      imageUrls.push(await uploadToSupabase(file, 'marketplace-images', 'goods/'));
    }
    const result = await pool.query(
      'INSERT INTO marketplace_goods (seller_id, title, description, price, category, condition, location, images) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [req.user.userId, title, description, price, category, condition, location, imageUrls]
    );
    setImmediate(() => awardXP(req.user.userId, 'item_listed', `good:${result.rows[0].id}`));
    res.json({ success: true, item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/reviews — award XP for leaving a review
app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { itemId, rating, comment, reviewedUserId } = req.body;
  if (!itemId || !rating) return res.status(400).json({ success: false, message: 'Item ID and rating required' });
  try {
    const insert = await pool.query(
      `INSERT INTO reviews (marketplace_item_id, reviewer_id, reviewed_user_id, rating, comment)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, marketplace_item_id, reviewer_id, rating, comment, created_at`,
      [itemId, req.user.userId, reviewedUserId, rating, comment]
    );
    const review = insert.rows[0];
    const withUser = await pool.query(
      `SELECT $1::int AS id, $2::int AS reviewer_id, $3::int AS marketplace_item_id,
              $4::int AS rating, $5::text AS comment, $6::timestamp AS created_at,
              u.full_name AS reviewer_name, u.profile_image_url AS reviewer_image
       FROM users u WHERE u.id=$2`,
      [review.id, review.reviewer_id, review.marketplace_item_id,
       review.rating, review.comment, review.created_at]
    );
    setImmediate(() => awardXP(req.user.userId, 'review_given', `review:${review.id}`));
    res.json({ success: true, review: withUser.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/assignments/:id/submit — award XP
app.post('/api/assignments/:id/submit', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE assignments SET status='submitted', submitted_at=NOW()
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Assignment not found' });
    setImmediate(() => awardXP(req.user.userId, 'assignment_submitted', `assignment:${req.params.id}`));
    res.json({ success: true, assignment: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/study-tasks/:taskId/complete — award XP
app.post('/api/study-tasks/:taskId/complete', authMiddleware, async (req, res) => {
  const { notes } = req.body;
  try {
    const result = await pool.query(
      `UPDATE study_tasks st
       SET completed=true, completed_at=NOW(), notes=$1
       FROM study_plans sp
       WHERE st.id=$2 AND st.study_plan_id=sp.id AND sp.user_id=$3
       RETURNING st.*`,
      [notes, req.params.taskId, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Task not found' });
    await pool.query(
      `UPDATE study_plans sp
       SET progress_percentage=(
         SELECT (COUNT(*) FILTER (WHERE completed=true)::DECIMAL / COUNT(*))*100
         FROM study_tasks WHERE study_plan_id=sp.id
       )
       WHERE id=(SELECT study_plan_id FROM study_tasks WHERE id=$1)`,
      [req.params.taskId]
    );
    setImmediate(() => awardXP(req.user.userId, 'study_task_completed', `task:${req.params.taskId}`));
    res.json({ success: true, task: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// OVERRIDE: POST /api/library/:id/upvote — award XP to uploader when upvoted
app.post('/api/library/:id/upvote', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const existing = await pool.query(
      "SELECT id FROM library_interactions WHERE user_id=$1 AND resource_id=$2 AND interaction_type='upvote'",
      [req.user.userId, id]
    );
    if (existing.rows.length) {
      await pool.query('DELETE FROM library_interactions WHERE id=$1', [existing.rows[0].id]);
      return res.json({ success: true, action: 'removed' });
    }
    await pool.query(
      "INSERT INTO library_interactions (user_id, resource_id, interaction_type) VALUES ($1,$2,'upvote')",
      [req.user.userId, id]
    );
    // Award XP to uploader
    const uploader = await pool.query('SELECT uploader_id FROM library_resources WHERE id=$1', [id]);
    if (uploader.rows.length && uploader.rows[0].uploader_id !== req.user.userId) {
      setImmediate(() => {
        awardXP(uploader.rows[0].uploader_id, 'upvote_received', `resource:${id}`);
        awardXP(req.user.userId, 'library_upvote_given', `resource:${id}`);
      });
    }
    res.json({ success: true, action: 'added' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// STUDY GROUPS — JOIN (separate from create, awards join XP)
// ============================================================================
app.post('/api/study-groups/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const uid = req.user.userId;
  try {
    const group = await pool.query(
      'SELECT id, max_members FROM study_groups WHERE id=$1',
      [id]
    );
    if (!group.rows.length) return res.status(404).json({ success: false, message: 'Group not found' });
    const memberCount = await pool.query(
      'SELECT COUNT(*) FROM study_group_members WHERE group_id=$1',
      [id]
    );
    if (parseInt(memberCount.rows[0].count) >= group.rows[0].max_members) {
      return res.status(400).json({ success: false, message: 'Group is full' });
    }
    const existing = await pool.query(
      'SELECT id FROM study_group_members WHERE group_id=$1 AND user_id=$2',
      [id, uid]
    );
    if (existing.rows.length) {
      return res.status(400).json({ success: false, message: 'Already a member' });
    }
    await pool.query(
      'INSERT INTO study_group_members (group_id, user_id, role) VALUES ($1,$2,$3)',
      [id, uid, 'member']
    );
    setImmediate(() => awardXP(uid, 'study_group_joined', `group:${id}`));
    res.json({ success: true, message: 'Joined group' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// COMMENT LIKES
// ============================================================================

app.post('/api/library/comments/:id/like', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  try {
    const existing = await pool.query(
      'SELECT id FROM library_comment_likes WHERE comment_id=$1 AND user_id=$2',
      [req.params.id, uid]
    );
    if (existing.rows.length) {
      await pool.query('DELETE FROM library_comment_likes WHERE id=$1', [existing.rows[0].id]);
      return res.json({ success: true, liked: false });
    }
    await pool.query(
      'INSERT INTO library_comment_likes (comment_id, user_id) VALUES ($1,$2)',
      [req.params.id, uid]
    );
    res.json({ success: true, liked: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// PROFILE — update with all onboarding + extended fields
// ============================================================================

app.patch('/api/auth/profile', authMiddleware, async (req, res) => {
  const { fullName, studentId, institution, phone, bio, programme, yearOfStudy } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users
       SET full_name=$1, student_id=$2, institution=$3, phone=$4, bio=$5,
           programme=$6, year_of_study=$7, updated_at=NOW()
       WHERE id=$8
       RETURNING id, email, full_name, student_id, institution, phone, bio,
                 is_course_rep, programme, year_of_study, xp_points, level`,
      [fullName, studentId, institution, phone, bio,
       programme||null, yearOfStudy||null, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user: result.rows[0], message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// TIMETABLE — PATCH (missing in original, added here properly)
// ============================================================================

app.patch('/api/timetable/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  const allowed = ['title','day_of_week','start_time','end_time','location',
                   'course_code','instructor','notes','color','notification_enabled',
                   'notification_minutes_before','building','room_number'];
  try {
    const fields = [];
    const values = [];
    let n = 1;
    for (const key of allowed) {
      if (updates[key] !== undefined) {
        fields.push(`${key}=$${n++}`);
        values.push(updates[key]);
      }
    }
    if (!fields.length) return res.status(400).json({ success: false, message: 'No valid fields provided' });
    values.push(id, req.user.userId);
    const result = await pool.query(
      `UPDATE timetables SET ${fields.join(',')}
       WHERE id=$${n} AND user_id=$${n+1} RETURNING *`,
      values
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Entry not found' });
    res.json({ success: true, entry: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// MISC UTILITY ROUTES
// ============================================================================

// GET /api/stats/platform — public platform stats
app.get('/api/stats/platform', async (req, res) => {
  try {
    const [users, resources, groups, events] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM library_resources WHERE is_public=true'),
      pool.query('SELECT COUNT(*) FROM study_groups WHERE is_private=false'),
      pool.query('SELECT COUNT(*) FROM school_events'),
    ]);
    res.json({
      success: true,
      stats: {
        totalUsers:     parseInt(users.rows[0].count),
        totalResources: parseInt(resources.rows[0].count),
        totalGroups:    parseInt(groups.rows[0].count),
        totalEvents:    parseInt(events.rows[0].count),
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/library/:id — get single resource detail
app.get('/api/library/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lr.*, u.full_name AS uploader_name, u.profile_image_url AS uploader_image,
              (SELECT COUNT(*) FROM library_interactions WHERE resource_id=lr.id AND interaction_type='upvote') AS upvotes,
              (SELECT COUNT(*) FROM library_interactions WHERE resource_id=lr.id AND interaction_type='downvote') AS downvotes,
              EXISTS(SELECT 1 FROM library_interactions WHERE resource_id=lr.id AND user_id=$2 AND interaction_type='upvote') AS has_upvoted,
              EXISTS(SELECT 1 FROM library_bookmarks WHERE resource_id=lr.id AND user_id=$2) AS is_bookmarked
       FROM library_resources lr
       JOIN users u ON u.id=lr.uploader_id
       WHERE lr.id=$1 AND (lr.is_public=true OR lr.uploader_id=$2)`,
      [req.params.id, req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Resource not found' });
    // Increment download counter on fetch
    await pool.query('UPDATE library_resources SET downloads=downloads+1 WHERE id=$1', [req.params.id]);
    res.json({ success: true, resource: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Seed badges on startup (non-blocking)
setImmediate(async () => {

// ============================================================================
// MIGRATE-V4 — preferences, contacts, tour, admin
// ============================================================================
app.post('/api/migrate-v4', async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_preferences (
        user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        study_style   VARCHAR(30)  DEFAULT 'visual',
        noise_pref    VARCHAR(20)  DEFAULT 'quiet',
        collab_pref   VARCHAR(20)  DEFAULT 'both',
        interests     JSONB        DEFAULT '[]',
        study_times   JSONB        DEFAULT '[]',
        goals         JSONB        DEFAULT '[]',
        notifications_enabled BOOLEAN DEFAULT TRUE,
        updated_at    TIMESTAMPTZ  DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS user_tour_progress (
        user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        completed    BOOLEAN  DEFAULT FALSE,
        steps_seen   JSONB    DEFAULT '[]',
        created_at   TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS phone_contacts (
        id            SERIAL PRIMARY KEY,
        user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
        contact_phone VARCHAR(50)  NOT NULL,
        contact_name  VARCHAR(200),
        found_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, contact_phone)
      );
      CREATE TABLE IF NOT EXISTS admin_uploads (
        id           SERIAL PRIMARY KEY,
        admin_id     INTEGER REFERENCES users(id),
        type         VARCHAR(30) NOT NULL,
        title        VARCHAR(300),
        program      VARCHAR(200),
        institution  VARCHAR(200),
        year         VARCHAR(10),
        semester     VARCHAR(20),
        file_url     TEXT,
        description  TEXT,
        meta         JSONB DEFAULT '{}',
        created_at   TIMESTAMPTZ DEFAULT NOW()
      );
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin       BOOLEAN  DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_complete BOOLEAN DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS interests      JSONB    DEFAULT '[]';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS study_style    VARCHAR(30);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS noise_pref     VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS collab_pref    VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS university     VARCHAR(300);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS program_name   VARCHAR(300);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS phone          VARCHAR(50);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS login_streak   INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS xp_points      INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active    TIMESTAMPTZ DEFAULT NOW();
      ALTER TABLE users ADD COLUMN IF NOT EXISTS status_emoji   VARCHAR(8)  DEFAULT '📚';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS status_text    VARCHAR(100);
    `);
    res.json({ success: true, message: 'V4 migration complete' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// USER PREFERENCES
// ============================================================================
app.get('/api/preferences', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM user_preferences WHERE user_id=$1', [req.user.userId]);
    res.json({ success: true, preferences: rows[0] || null });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.put('/api/preferences', authMiddleware, async (req, res) => {
  const { studyStyle, noisePref, collabPref, interests, studyTimes, goals } = req.body;
  try {
    await pool.query(
      `INSERT INTO user_preferences(user_id,study_style,noise_pref,collab_pref,interests,study_times,goals,updated_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
       ON CONFLICT(user_id) DO UPDATE SET
         study_style=$2,noise_pref=$3,collab_pref=$4,interests=$5,study_times=$6,goals=$7,updated_at=NOW()`,
      [req.user.userId, studyStyle||'visual', noisePref||'quiet', collabPref||'both',
       JSON.stringify(interests||[]), JSON.stringify(studyTimes||[]), JSON.stringify(goals||[])]
    );
    if (interests?.length) {
      await pool.query('UPDATE users SET interests=$1 WHERE id=$2', [JSON.stringify(interests), req.user.userId]);
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.patch('/api/onboarding/complete', authMiddleware, async (req, res) => {
  const { university, programName, studyStyle, noisePref, collabPref, interests, studyTimes, goals } = req.body;
  try {
    await pool.query(
      `UPDATE users SET onboarding_complete=TRUE, university=$2, program_name=$3,
         study_style=$4, noise_pref=$5, collab_pref=$6, interests=$7
       WHERE id=$1`,
      [req.user.userId, university||null, programName||null, studyStyle||null,
       noisePref||null, collabPref||null, JSON.stringify(interests||[])]
    );
    if (studyTimes || goals) {
      await pool.query(
        `INSERT INTO user_preferences(user_id,study_times,goals,study_style,noise_pref,collab_pref,interests)
         VALUES($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT(user_id) DO UPDATE SET study_times=$2,goals=$3,study_style=$4,noise_pref=$5,collab_pref=$6,interests=$7`,
        [req.user.userId, JSON.stringify(studyTimes||[]), JSON.stringify(goals||[]),
         studyStyle||'visual', noisePref||'quiet', collabPref||'both', JSON.stringify(interests||[])]
      );
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// PLATFORM TOUR
// ============================================================================
app.get('/api/tour', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM user_tour_progress WHERE user_id=$1', [req.user.userId]);
    res.json({ success: true, tour: rows[0] || null });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/tour/complete', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO user_tour_progress(user_id,completed) VALUES($1,TRUE)
       ON CONFLICT(user_id) DO UPDATE SET completed=TRUE`,
      [req.user.userId]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// PHONE-BASED CONTACTS
// ============================================================================

// POST /api/contacts/sync — client sends list of phone numbers, server returns matched users
app.post('/api/contacts/sync', authMiddleware, async (req, res) => {
  const { contacts } = req.body; // [{name, phone}]
  if (!Array.isArray(contacts) || contacts.length === 0) {
    return res.json({ success: true, matches: [] });
  }
  try {
    const phones = contacts.map(c => c.phone?.replace(/\s|-|\(|\)/g, '') || '').filter(Boolean);
    if (!phones.length) return res.json({ success: true, matches: [] });

    const { rows: matches } = await pool.query(
      `SELECT u.id, u.full_name, u.profile_image_url, u.university, u.program_name,
              u.status_emoji, u.xp_points, u.phone,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=u.id) AS is_following
       FROM users u
       WHERE REGEXP_REPLACE(u.phone, '[\\s\\-\\(\\)]', '', 'g') = ANY($2)
         AND u.id != $1`,
      [req.user.userId, phones]
    );

    // Store the matches for quick lookup later
    for (const c of contacts) {
      const phone = c.phone?.replace(/\s|-|\(|\)/g, '') || '';
      if (!phone) continue;
      const found = matches.find(m => m.phone?.replace(/\s|-|\(|\)/g, '') === phone);
      await pool.query(
        `INSERT INTO phone_contacts(user_id,contact_phone,contact_name,found_user_id)
         VALUES($1,$2,$3,$4) ON CONFLICT(user_id,contact_phone) DO UPDATE SET
           contact_name=$3, found_user_id=$4`,
        [req.user.userId, phone, c.name || null, found?.id || null]
      );
    }

    res.json({ success: true, matches });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// GET /api/contacts/matches — get previously synced matches
app.get('/api/contacts/matches', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT pc.contact_name, pc.contact_phone,
              u.id, u.full_name, u.profile_image_url, u.university, u.program_name, u.status_emoji,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=u.id) AS is_following,
              EXISTS(SELECT 1 FROM direct_messages WHERE (sender_id=$1 AND receiver_id=u.id) OR (sender_id=u.id AND receiver_id=$1) LIMIT 1) AS has_chat
       FROM phone_contacts pc
       JOIN users u ON u.id = pc.found_user_id
       WHERE pc.user_id=$1 AND pc.found_user_id IS NOT NULL
       ORDER BY u.full_name`,
      [req.user.userId]
    );
    res.json({ success: true, contacts: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// UNIVERSAL SEARCH
// ============================================================================
app.get('/api/search', authMiddleware, async (req, res) => {
  const { q, type = 'all' } = req.query;
  if (!q || q.trim().length < 2) return res.json({ success: true, results: {} });
  const term = `%${q.trim()}%`;
  const uid = req.user.userId;
  try {
    const results = {};

    if (type === 'all' || type === 'users') {
      const { rows } = await pool.query(
        `SELECT id, full_name, profile_image_url, university, program_name, xp_points, status_emoji,
                EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$2 AND following_id=u.id) AS is_following
         FROM users u WHERE full_name ILIKE $1 AND id!=$2 LIMIT 8`,
        [term, uid]
      );
      results.users = rows;
    }

    if (type === 'all' || type === 'resources') {
      const { rows } = await pool.query(
        `SELECT lr.id, lr.title, lr.file_type, lr.file_url, lr.resource_type, lr.upvotes,
                u.full_name AS uploader
         FROM library_resources lr JOIN users u ON u.id=lr.uploader_id
         WHERE (lr.title ILIKE $1 OR lr.tags ILIKE $1 OR lr.description ILIKE $1) LIMIT 8`,
        [term]
      );
      results.resources = rows;
    }

    if (type === 'all' || type === 'classes') {
      const { rows } = await pool.query(
        `SELECT cs.id, cs.course_name, cs.course_code, cs.institution, cs.semester,
                COUNT(csm.user_id)::int AS members,
                EXISTS(SELECT 1 FROM class_space_members WHERE user_id=$2 AND class_space_id=cs.id) AS joined
         FROM class_spaces cs LEFT JOIN class_space_members csm ON csm.class_space_id=cs.id
         WHERE cs.course_name ILIKE $1 OR cs.course_code ILIKE $1
         GROUP BY cs.id LIMIT 8`,
        [term, uid]
      );
      results.classes = rows;
    }

    if (type === 'all' || type === 'groups') {
      const { rows } = await pool.query(
        `SELECT sg.id, sg.name, sg.description, sg.subject, sg.is_public,
                COUNT(sgm.user_id)::int AS members,
                EXISTS(SELECT 1 FROM study_group_members WHERE user_id=$2 AND group_id=sg.id) AS joined
         FROM study_groups sg LEFT JOIN study_group_members sgm ON sgm.group_id=sg.id
         WHERE (sg.name ILIKE $1 OR sg.subject ILIKE $1 OR sg.description ILIKE $1)
           AND sg.is_public=TRUE
         GROUP BY sg.id LIMIT 6`,
        [term, uid]
      );
      results.groups = rows;
    }

    if (type === 'all' || type === 'posts') {
      const { rows } = await pool.query(
        `SELECT cp.id, cp.text, cp.category, cp.created_at, cp.likes,
                u.full_name, u.profile_image_url
         FROM campus_pulse_posts cp JOIN users u ON u.id=cp.user_id
         WHERE cp.text ILIKE $1
         ORDER BY cp.created_at DESC LIMIT 6`,
        [term]
      );
      results.posts = rows;
    }

    if (type === 'all' || type === 'marketplace') {
      const { rows } = await pool.query(
        `SELECT id, title, description, price, condition, images
         FROM marketplace_goods WHERE title ILIKE $1 OR description ILIKE $1 LIMIT 6`,
        [term]
      );
      results.goods = rows;
    }

    if (type === 'all' || type === 'assignments') {
      const { rows } = await pool.query(
        `SELECT id, title, subject, due_date, status, priority
         FROM assignments WHERE user_id=$2 AND (title ILIKE $1 OR subject ILIKE $1) LIMIT 6`,
        [term, uid]
      );
      results.assignments = rows;
    }

    res.json({ success: true, results, query: q.trim() });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// PEOPLE RECOMMENDATIONS (based on same uni + program + interests)
// ============================================================================
app.get('/api/recommendations/people', authMiddleware, async (req, res) => {
  const uid = req.user.userId;
  try {
    const { rows: me } = await pool.query(
      'SELECT university, program_name, interests FROM users WHERE id=$1', [uid]
    );
    if (!me.length) return res.json({ success: true, people: [] });
    const { university, program_name } = me[0];

    const { rows } = await pool.query(
      `SELECT u.id, u.full_name, u.profile_image_url, u.university, u.program_name,
              u.xp_points, u.status_emoji, u.phone,
              EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=u.id) AS is_following,
              CASE WHEN u.university=$2 AND u.program_name=$3 THEN 3
                   WHEN u.university=$2 THEN 2
                   ELSE 1 END AS match_score
       FROM users u
       WHERE u.id != $1
         AND (u.university=$2 OR u.program_name=$3)
         AND NOT EXISTS(SELECT 1 FROM user_follows WHERE follower_id=$1 AND following_id=u.id)
       ORDER BY match_score DESC, u.xp_points DESC
       LIMIT 20`,
      [uid, university, program_name]
    );
    res.json({ success: true, people: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// ADMIN PANEL
// ============================================================================

// Admin middleware
const adminMiddleware = (req, res, next) => {
  if (!req.user?.userId) return res.status(401).json({ success: false, message: 'Unauthorized' });
  pool.query('SELECT is_admin FROM users WHERE id=$1', [req.user.userId])
    .then(({ rows }) => {
      if (!rows[0]?.is_admin) return res.status(403).json({ success: false, message: 'Admin access required' });
      next();
    })
    .catch(e => res.status(500).json({ success: false, error: e.message }));
};

// POST /api/admin/make-admin  { userId } — dev only, no auth check
app.post('/api/admin/make-admin', async (req, res) => {
  const { userId, secret } = req.body;
  if (secret !== (process.env.ADMIN_SECRET || 'studenthub_admin_2024')) {
    return res.status(403).json({ success: false, message: 'Invalid secret' });
  }
  try {
    await pool.query('UPDATE users SET is_admin=TRUE WHERE id=$1', [userId]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// GET /api/admin/stats
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const queries = [
      pool.query('SELECT COUNT(*)::int AS total FROM users'),
      pool.query(`SELECT COUNT(*)::int AS today FROM users WHERE created_at >= CURRENT_DATE`),
      pool.query('SELECT COUNT(*)::int AS total FROM class_spaces'),
      pool.query('SELECT COUNT(*)::int AS total FROM library_resources'),
      pool.query('SELECT COUNT(*)::int AS total FROM assignments'),
      pool.query(`SELECT COUNT(*)::int AS active FROM users WHERE last_active >= NOW()-INTERVAL '24 hours'`),
      pool.query(`SELECT COUNT(*)::int AS total FROM campus_pulse_posts`),
      pool.query(`SELECT COUNT(*)::int AS total FROM study_groups`),
    ];
    const results = await Promise.all(queries);
    res.json({
      success: true,
      stats: {
        totalUsers:      results[0].rows[0].total,
        newUsersToday:   results[1].rows[0].today,
        totalClasses:    results[2].rows[0].total,
        totalResources:  results[3].rows[0].total,
        totalAssignments:results[4].rows[0].total,
        activeUsers24h:  results[5].rows[0].active,
        totalPosts:      results[6].rows[0].total,
        totalGroups:     results[7].rows[0].total,
      }
    });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// GET /api/admin/users?limit=50&page=1
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { limit = 50, page = 1, q } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  try {
    const term = q ? `%${q}%` : null;
    const { rows } = await pool.query(
      `SELECT id, full_name, email, university, program_name, is_admin,
              xp_points, login_streak, created_at, last_active, onboarding_complete,
              (SELECT COUNT(*)::int FROM class_space_members WHERE user_id=u.id) AS classes_joined
       FROM users u
       ${term ? 'WHERE full_name ILIKE $3 OR email ILIKE $3 OR university ILIKE $3' : ''}
       ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      term ? [limit, offset, term] : [limit, offset]
    );
    const { rows: cnt } = await pool.query(`SELECT COUNT(*)::int AS total FROM users`);
    res.json({ success: true, users: rows, total: cnt[0].total });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// POST /api/admin/upload-timetable — upload program timetable
app.post('/api/admin/upload-timetable', authMiddleware, adminMiddleware, async (req, res) => {
  const { title, program, institution, year, semester, timetableData, description } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO admin_uploads(admin_id, type, title, program, institution, year, semester, description, meta)
       VALUES($1,'timetable',$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.user.userId, title, program, institution, year, semester, description,
       JSON.stringify(timetableData || {})]
    );

    // If timetableData has entries, create actual timetable entries for students in the program
    if (timetableData?.entries?.length) {
      const { rows: students } = await pool.query(
        'SELECT id FROM users WHERE program_name ILIKE $1 AND university ILIKE $2',
        [`%${program}%`, `%${institution}%`]
      );
      let created = 0;
      for (const student of students) {
        for (const entry of timetableData.entries) {
          try {
            await pool.query(
              `INSERT INTO timetables(user_id, day_of_week, start_time, end_time, title, location_name, color)
               VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
              [student.id, entry.day, entry.startTime, entry.endTime,
               entry.courseName, entry.location || null, entry.color || '#5b4efa']
            );
            created++;
          } catch {}
        }
      }
      rows[0].studentsUpdated = students.length;
      rows[0].entriesCreated = created;
    }

    res.json({ success: true, upload: rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// POST /api/admin/upload-material — upload course material for students
app.post('/api/admin/upload-material', authMiddleware, adminMiddleware, async (req, res) => {
  const { title, program, institution, year, semester, fileUrl, description, courseCode } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO admin_uploads(admin_id,type,title,program,institution,year,semester,description,file_url,meta)
       VALUES($1,'material',$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.userId, title, program, institution, year, semester, description,
       fileUrl || null, JSON.stringify({ courseCode: courseCode || null })]
    );

    // Also add to library_resources as admin-uploaded
    if (fileUrl) {
      await pool.query(
        `INSERT INTO library_resources(uploader_id, title, description, course_code, resource_type, file_url, is_public)
         VALUES($1,$2,$3,$4,'admin_upload',$5,TRUE)`,
        [req.user.userId, title, description || null, courseCode || null, fileUrl]
      ).catch(() => {});
    }

    res.json({ success: true, upload: rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// GET /api/admin/uploads — list all admin uploads
app.get('/api/admin/uploads', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT au.*, u.full_name AS admin_name
       FROM admin_uploads au JOIN users u ON u.id=au.admin_id
       ORDER BY au.created_at DESC LIMIT 100`
    );
    res.json({ success: true, uploads: rows });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// DELETE /api/admin/uploads/:id
app.delete('/api/admin/uploads/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM admin_uploads WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// POST /api/admin/announcement  — send notification to all users or specific program
app.post('/api/admin/announcement', authMiddleware, adminMiddleware, async (req, res) => {
  const { title, message, program, institution } = req.body;
  if (!title || !message) return res.status(400).json({ success: false, message: 'Title and message required' });
  try {
    let q = 'SELECT id FROM users';
    const params = [];
    if (program) {
      q += ' WHERE program_name ILIKE $1';
      params.push(`%${program}%`);
      if (institution) { q += ' AND university ILIKE $2'; params.push(`%${institution}%`); }
    }
    const { rows: users } = await pool.query(q, params);
    let sent = 0;
    for (const u of users) {
      await pool.query(
        `INSERT INTO notifications(user_id, type, title, message) VALUES($1,'announcement',$2,$3)`,
        [u.id, title, message]
      ).catch(() => {});
      sent++;
    }
    res.json({ success: true, sent });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================================
// SHARE RESOURCE AS DM
// ============================================================================
app.post('/api/share/resource-dm', authMiddleware, async (req, res) => {
  const { resourceId, recipientId, message } = req.body;
  try {
    const { rows: resource } = await pool.query('SELECT * FROM library_resources WHERE id=$1', [resourceId]);
    if (!resource.length) return res.status(404).json({ success: false });
    const shareText = `📚 Shared a resource: *${resource[0].title}* ${message ? `\n${message}` : ''}\n[View in Library: /library/${resourceId}]`;
    const { rows } = await pool.query(
      `INSERT INTO direct_messages(sender_id, receiver_id, message, message_type, meta)
       VALUES($1,$2,$3,'resource',$4) RETURNING *`,
      [req.user.userId, recipientId, shareText, JSON.stringify({ resourceId, title: resource[0].title, fileUrl: resource[0].file_url })]
    );
    res.json({ success: true, message: rows[0] });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});


// ============================================================================
// CLOSING
// ============================================================================
});
});
