// ============================================
// STUDENT PLATFORM - COMPLETE BACKEND API
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

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================
// MIDDLEWARE
// ============================================

// Trust proxy for Railway
app.set('trust proxy', 1);

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
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
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
// SUPABASE CLIENT
// ============================================

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // Use service role key for server-side operations
);

// Test connection
(async () => {
  try {
    const { data, error } = await supabase.from('users').select('count').limit(1);
    if (error) throw error;
    console.log('✅ Supabase connected successfully');
  } catch (error) {
    console.error('❌ Supabase connection error:', error.message);
  }
})();

// Helper function for database queries
const db = {
  query: async (text, params) => {
    // This is a wrapper to maintain compatibility with existing code
    // You'll need to convert SQL queries to Supabase queries
    throw new Error('Use Supabase client methods instead of raw SQL');
  }
};

app.locals.db = db;

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

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName, studentId, institution, isCourseRep } = req.body;
  try {
    // Check if user exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        email,
        password_hash: passwordHash,
        full_name: fullName,
        student_id: studentId,
        institution,
        is_course_rep: isCourseRep || false
      }])
      .select('id, email, full_name, is_course_rep')
      .single();

    if (error) throw error;

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({ success: true, token, user });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

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
        isCourseRep: user.is_course_rep
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, full_name, student_id, institution, phone, bio, profile_image_url, is_course_rep')
      .eq('id', req.user.userId)
      .single();

    if (error || !user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// CLASS SPACES ROUTES
app.post('/api/class-spaces', authMiddleware, async (req, res) => {
  const { courseCode, courseName, description, institution, semester, academicYear } = req.body;
  try {
    const { data: user } = await supabase
      .from('users')
      .select('is_course_rep')
      .eq('id', req.user.userId)
      .single();

    if (!user?.is_course_rep) {
      return res.status(403).json({ success: false, message: 'Only course reps can create class spaces' });
    }

    const { data: classSpace, error } = await supabase
      .from('class_spaces')
      .insert([{
        course_rep_id: req.user.userId,
        course_code: courseCode,
        course_name: courseName,
        description,
        institution,
        semester,
        academic_year: academicYear
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, classSpace });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/class-spaces', authMiddleware, async (req, res) => {
  try {
    const { data: classSpaces, error } = await supabase
      .from('class_spaces')
      .select(`
        *,
        users!course_rep_id (full_name)
      `)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({ success: true, classSpaces });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/class-spaces/:id/join', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase
      .from('class_space_members')
      .upsert({ class_space_id: id, user_id: req.user.userId });

    if (error) throw error;

    res.json({ success: true, message: 'Joined class space' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/class-spaces/:id/resources', authMiddleware, upload.single('file'), async (req, res) => {
  const { id } = req.params;
  const { title, description, resourceType } = req.body;
  try {
    const fileUrl = `/uploads/${req.file.filename}`;
    
    const { data: resource, error } = await supabase
      .from('class_resources')
      .insert([{
        class_space_id: id,
        uploader_id: req.user.userId,
        title,
        description,
        file_url: fileUrl,
        file_type: req.file.mimetype,
        file_size: req.file.size,
        resource_type: resourceType
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, resource });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/class-spaces/:id/resources', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const { data: resources, error } = await supabase
      .from('class_resources')
      .select(`
        *,
        users!uploader_id (full_name)
      `)
      .eq('class_space_id', id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({ success: true, resources });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// LIBRARY ROUTES
app.post('/api/library', authMiddleware, upload.single('file'), async (req, res) => {
  const { title, description, subject } = req.body;
  try {
    const fileUrl = `/uploads/${req.file.filename}`;
    
    const { data: resource, error } = await supabase
      .from('library_resources')
      .insert([{
        uploader_id: req.user.userId,
        title,
        description,
        subject,
        file_url: fileUrl,
        file_type: req.file.mimetype,
        file_size: req.file.size
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, resource });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/library', authMiddleware, async (req, res) => {
  try {
    const { data: resources, error } = await supabase
      .from('library_resources')
      .select(`
        *,
        users!uploader_id (full_name)
      `)
      .eq('is_public', true)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({ success: true, resources });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// MARKETPLACE ROUTES
app.post('/api/marketplace/goods', authMiddleware, async (req, res) => {
  const { title, description, price, category, condition, location } = req.body;
  try {
    const { data: item, error } = await supabase
      .from('marketplace_goods')
      .insert([{
        seller_id: req.user.userId,
        title,
        description,
        price,
        category,
        condition,
        location
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, item });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/marketplace/goods', authMiddleware, async (req, res) => {
  try {
    const { data: items, error } = await supabase
      .from('marketplace_goods')
      .select(`
        *,
        users!seller_id (full_name, phone)
      `)
      .eq('status', 'available')
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({ success: true, items });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/marketplace/services', authMiddleware, async (req, res) => {
  const { title, description, price, category, serviceCategory, duration, availability } = req.body;
  try {
    const { data: service, error } = await supabase
      .from('marketplace_services')
      .insert([{
        provider_id: req.user.userId,
        title,
        description,
        price,
        category,
        service_category: serviceCategory || 'general',
        duration,
        availability
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, service });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/marketplace/services', authMiddleware, async (req, res) => {
  try {
    const { data: services, error } = await supabase
      .from('marketplace_services')
      .select(`
        *,
        users!provider_id (full_name, phone)
      `)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({ success: true, services });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// STUDY GROUPS ROUTES
app.post('/api/study-groups', authMiddleware, async (req, res) => {
  const { name, description, subject, maxMembers, isPrivate } = req.body;
  try {
    const { data: group, error } = await supabase
      .from('study_groups')
      .insert([{
        creator_id: req.user.userId,
        name,
        description,
        subject,
        max_members: maxMembers,
        is_private: isPrivate
      }])
      .select()
      .single();

    if (error) throw error;

    // Add creator as admin member
    await supabase
      .from('study_group_members')
      .insert([{
        group_id: group.id,
        user_id: req.user.userId,
        role: 'admin'
      }]);

    res.json({ success: true, group });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/study-groups', authMiddleware, async (req, res) => {
  try {
    const { data: groups, error } = await supabase
      .from('study_groups')
      .select(`
        *,
        users!creator_id (full_name)
      `)
      .eq('is_private', false)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({ success: true, groups });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// TIMETABLE ROUTES
app.post('/api/timetable', authMiddleware, async (req, res) => {
  const { title, dayOfWeek, startTime, endTime, location, courseCode, instructor, notes, color } = req.body;
  try {
    const { data: entry, error } = await supabase
      .from('timetables')
      .insert([{
        user_id: req.user.userId,
        title,
        day_of_week: dayOfWeek,
        start_time: startTime,
        end_time: endTime,
        location,
        course_code: courseCode,
        instructor,
        notes,
        color
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, entry });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/timetable', authMiddleware, async (req, res) => {
  try {
    const { data: entries, error } = await supabase
      .from('timetables')
      .select('*')
      .eq('user_id', req.user.userId)
      .order('day_of_week')
      .order('start_time');

    if (error) throw error;

    res.json({ success: true, entries });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// CLASS TIMETABLE ROUTES
app.post('/api/class-spaces/:id/timetable', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { dayOfWeek, startTime, endTime, locationName, locationAddress, locationLat, locationLng, roomNumber, building, notes } = req.body;
  try {
    const { data: classSpace } = await supabase
      .from('class_spaces')
      .select('course_rep_id')
      .eq('id', id)
      .single();

    if (!classSpace || classSpace.course_rep_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the course rep can set the class timetable' });
    }

    const { data: entry, error } = await supabase
      .from('class_timetables')
      .insert([{
        class_space_id: id,
        day_of_week: dayOfWeek,
        start_time: startTime,
        end_time: endTime,
        location_name: locationName,
        location_address: locationAddress,
        location_lat: locationLat,
        location_lng: locationLng,
        room_number: roomNumber,
        building,
        notes
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, entry });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/class-spaces/:id/timetable', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const { data: entries, error } = await supabase
      .from('class_timetables')
      .select('*')
      .eq('class_space_id', id)
      .order('day_of_week')
      .order('start_time');

    if (error) throw error;

    res.json({ success: true, entries });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/class-spaces/:classId/timetable/:entryId', authMiddleware, async (req, res) => {
  const { classId, entryId } = req.params;
  try {
    const { data: classSpace } = await supabase
      .from('class_spaces')
      .select('course_rep_id')
      .eq('id', classId)
      .single();

    if (!classSpace || classSpace.course_rep_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Only the course rep can delete timetable entries' });
    }

    const { error } = await supabase
      .from('class_timetables')
      .delete()
      .eq('id', entryId)
      .eq('class_space_id', classId);

    if (error) throw error;

    res.json({ success: true, message: 'Timetable entry deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// HOMEWORK HELP ROUTES
app.post('/api/homework-help', authMiddleware, async (req, res) => {
  const { title, question, subject, classSpaceId } = req.body;
  try {
    const { data: helpRequest, error } = await supabase
      .from('homework_help')
      .insert([{
        student_id: req.user.userId,
        title,
        question,
        subject,
        class_space_id: classSpaceId
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, helpRequest });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/homework-help', authMiddleware, async (req, res) => {
  try {
    const { data: requests, error } = await supabase
      .from('homework_help')
      .select(`
        *,
        users!student_id (full_name)
      `)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({ success: true, requests });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/homework-help/:id/respond', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { response } = req.body;
  try {
    const { data: responseData, error } = await supabase
      .from('homework_responses')
      .insert([{
        help_request_id: id,
        responder_id: req.user.userId,
        response
      }])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, response: responseData });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ERROR HANDLING
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ success: false, message: err.message || 'Internal server error' });
});

// START SERVER
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
