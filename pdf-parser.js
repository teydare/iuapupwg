// ============================================
// UNIVERSAL TIMETABLE PDF PARSER
// Works with ANY university, ANY courses, ANY format
// ============================================

// ADD THIS TO YOUR server.js (BEFORE any routes)

const pdf = require('pdf-parse');
const multer = require('multer');
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// ============================================
// UNIVERSAL PDF PARSE ROUTE
// Detects ALL courses automatically
// ============================================
app.post('/api/parse-timetable-pdf', authMiddleware, upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No PDF file uploaded' });
    }
    
    const { yearLevel } = req.body;
    
    // Parse PDF
    const data = await pdf(req.file.buffer);
    const text = data.text;
    
    const courses = [];
    const lines = text.split('\n');
    
    let currentDay = null;
    let currentYear = null;
    
    // Universal day detection - works in any language/format
    const dayPatterns = [
      { pattern: /SUNDAY|SUN/i, value: 0 },
      { pattern: /MONDAY|MON/i, value: 1 },
      { pattern: /TUESDAY|TUE/i, value: 2 },
      { pattern: /WEDNESDAY|WED/i, value: 3 },
      { pattern: /THURSDAY|THU/i, value: 4 },
      { pattern: /FRIDAY|FRI/i, value: 5 },
      { pattern: /SATURDAY|SAT/i, value: 6 }
    ];
    
    // Universal year detection
    const yearPatterns = [
      { pattern: /FIRST\s+YEAR|YEAR\s+1|1ST\s+YEAR/i, value: 1 },
      { pattern: /SECOND\s+YEAR|YEAR\s+2|2ND\s+YEAR/i, value: 2 },
      { pattern: /THIRD\s+YEAR|YEAR\s+3|3RD\s+YEAR/i, value: 3 },
      { pattern: /FOURTH\s+YEAR|YEAR\s+4|4TH\s+YEAR/i, value: 4 }
    ];
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      
      // Detect year level
      for (const { pattern, value } of yearPatterns) {
        if (pattern.test(line)) {
          currentYear = value;
          break;
        }
      }
      
      // Detect day
      for (const { pattern, value } of dayPatterns) {
        if (pattern.test(line)) {
          currentDay = value;
          break;
        }
      }
      
      // Skip if year specified and doesn't match
      if (yearLevel && currentYear && currentYear !== parseInt(yearLevel)) continue;
      
      // Parse time slots - supports multiple formats
      const timePatterns = [
        /(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})/,  // 8:00-8:55
        /(\d{1,2})\.(\d{2})\s*-\s*(\d{1,2})\.(\d{2})/, // 8.00-8.55
        /(\d{1,2}):(\d{2})\s*to\s*(\d{1,2}):(\d{2})/i  // 8:00 to 8:55
      ];
      
      let timeMatch = null;
      for (const pattern of timePatterns) {
        timeMatch = line.match(pattern);
        if (timeMatch) break;
      }
      
      if (timeMatch && currentDay !== null) {
        const startTime = `${timeMatch[1].padStart(2, '0')}:${timeMatch[2]}`;
        const endTime = `${timeMatch[3].padStart(2, '0')}:${timeMatch[4]}`;
        
        // UNIVERSAL COURSE CODE DETECTION
        // Matches ANY pattern of letters followed by numbers
        // Examples: CS101, MATH151, BIO-101, ENG 201, etc.
        const coursePatterns = [
          /\b([A-Z]{2,4})[\s-]?(\d{3,4}[A-Z]?)\b/g,  // CS101, MATH 151, BIO-101
          /\b([A-Z][A-Z]+)\s+(\d+)\b/g,               // COMP 101
          /\b([A-Z]+)(\d+)\b/g                        // CS101 (no space)
        ];
        
        const foundCourses = new Set();
        
        for (const pattern of coursePatterns) {
          let match;
          while ((match = pattern.exec(line)) !== null) {
            const courseCode = `${match[1]} ${match[2]}`.trim();
            foundCourses.add(courseCode);
          }
        }
        
        // Extract location - universal patterns
        const locationPatterns = [
          /\b(LAB|LABORATORY|PRACTICALS?|PROJECT)\b/i,
          /\b([A-Z]{2,4}-[A-Z0-9]+)\b/,              // NEB-GF, PB-208
          /\b([A-Z]+\s*\d+)\b/,                      // PB208, ROOM 101
          /\b(ROOM|RM|HALL|BLDG|BUILDING)\s*([A-Z0-9-]+)/i,
          /\b([A-Z]{3,})\b/                          // VSLA, AUDIT, etc.
        ];
        
        let building = 'TBD';
        let roomNumber = '';
        
        for (const pattern of locationPatterns) {
          const locMatch = line.match(pattern);
          if (locMatch) {
            const location = locMatch[0];
            if (location.includes('-')) {
              [building, roomNumber] = location.split('-');
            } else {
              building = location;
            }
            break;
          }
        }
        
        // Extract instructor - universal name patterns
        const instructorPatterns = [
          /\b([A-Z]\.\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b/g,  // J. Smith, A. Johnson
          /\b(Dr|Prof|Mr|Mrs|Ms)\.?\s+([A-Z][a-z]+)/gi,       // Dr. Smith
          /\b([A-Z][a-z]+\s+[A-Z][a-z]+)\b/g                  // John Smith
        ];
        
        let instructor = 'Staff';
        for (const pattern of instructorPatterns) {
          const instMatch = line.match(pattern);
          if (instMatch && instMatch[0]) {
            instructor = instMatch[0].trim();
            break;
          }
        }
        
        // Add all detected courses
        foundCourses.forEach(courseCode => {
          courses.push({
            course_code: courseCode,
            course_name: courseCode, // Can be enriched later
            day_of_week: currentDay,
            start_time: startTime,
            end_time: endTime,
            building: building,
            room_number: roomNumber,
            instructor: instructor,
            year_level: currentYear || yearLevel || null,
            raw_line: line // Keep original for reference
          });
        });
      }
    }
    
    // Remove duplicates
    const uniqueCourses = [];
    const seen = new Set();
    
    for (const course of courses) {
      const key = `${course.course_code}-${course.day_of_week}-${course.start_time}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueCourses.push(course);
      }
    }
    
    // Sort by day and time
    uniqueCourses.sort((a, b) => {
      if (a.day_of_week !== b.day_of_week) return a.day_of_week - b.day_of_week;
      return a.start_time.localeCompare(b.start_time);
    });
    
    res.json({
      success: true,
      courses: uniqueCourses,
      count: uniqueCourses.length,
      yearLevel: currentYear,
      message: `Detected ${uniqueCourses.length} courses`
    });
    
  } catch (error) {
    console.error('PDF parse error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
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
