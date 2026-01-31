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
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================
// SUPABASE STORAGE CLIENT
// ============================================

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // Use service role key for server-side operations
);

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
        avgRating: parseFloat(avgRating.rows[0].avg)
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

app.get('/api/store/:sellerId', async (req, res) => {
  const { sellerId } = req.params;

  try {

    // ------------------------
    // Seller Info + Rating
    // ------------------------

    const sellerResult = await pool.query(`
      SELECT 
        u.id,
        u.full_name,
        u.profile_image_url,
        u.bio,
        u.created_at,

        COALESCE(AVG(r.rating),0)::numeric(10,1) as seller_rating,
        COUNT(r.id) as seller_review_count

      FROM users u
      LEFT JOIN reviews r 
        ON r.reviewed_user_id = u.id

      WHERE u.id = $1
      GROUP BY u.id
    `, [sellerId]);

    if (sellerResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Seller not found'
      });
    }

    const seller = sellerResult.rows[0];

    // ------------------------
    // Seller Items
    // ------------------------

    const itemsResult = await pool.query(`
      SELECT 
        g.*,

        COALESCE(AVG(r.rating),0)::numeric(10,1) as rating,
        COUNT(r.id) as review_count

      FROM marketplace_goods g

      LEFT JOIN reviews r
        ON r.marketplace_item_id = g.id

      WHERE g.seller_id = $1
      GROUP BY g.id
      ORDER BY g.created_at DESC
    `, [sellerId]);

    res.json({
      success: true,
      store: seller,
      items: itemsResult.rows
    });

  } catch (error) {
    console.error('Store load error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
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
// LIBRARY ROUTES WITH SUPABASE STORAGE
// ============================================

app.post('/api/library', authMiddleware, documentUpload.single('file'), async (req, res) => {
  const { title, description, subject } = req.body;
  
  try {
    // Upload to Supabase Storage
    const fileUrl = await uploadToSupabase(req.file, 'library-resources', '');
    
    const result = await pool.query(
      'INSERT INTO library_resources (uploader_id, title, description, subject, file_url, file_type, file_size) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.userId, title, description, subject, fileUrl, req.file.mimetype, req.file.size]
    );
    
    res.json({ success: true, resource: result.rows[0] });
  } catch (error) {
    console.error('Error uploading library resource:', error);
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

