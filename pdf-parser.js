// ============================================
// PDF TIMETABLE PARSER UTILITY
// Add this to your backend utilities
// npm install pdf-parse multer
// ============================================

const pdf = require('pdf-parse');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

// Parse timetable PDF and extract course information
async function parseTimetablePDF(pdfBuffer, targetProgram, yearLevel) {
  try {
    const data = await pdf(pdfBuffer);
    const text = data.text;
    
    const courses = [];
    const lines = text.split('\n');
    
    let currentDay = null;
    let currentYear = null;
    
    // Day mapping
    const dayMap = {
      'MONDAY': 1,
      'TUESDAY': 2,
      'WEDNESDAY': 3,
      'THURSDAY': 4,
      'FRIDAY': 5,
      'SATURDAY': 6,
      'SUNDAY': 0
    };
    
    // Program column indices (adjust based on your PDF structure)
    const programColumns = {
      'AEROSPACE': 0,
      'AGRIC': 1,
      'CHEMICAL': 2,
      'CIVIL': 3,
      'COMPUTER': 4,
      'ELECTRICAL': 5,
      'GEOMATIC': 6,
      'MECHANICAL': 7,
      'MATERIALS': 8,
      'PETROLEUM': 9
    };
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Detect year level
      if (line.includes('FIRST YEAR')) currentYear = 1;
      else if (line.includes('SECOND YEAR')) currentYear = 2;
      else if (line.includes('THIRD YEAR')) currentYear = 3;
      else if (line.includes('FOURTH YEAR')) currentYear = 4;
      
      // Detect day
      for (const [dayName, dayValue] of Object.entries(dayMap)) {
        if (line.includes(dayName)) {
          currentDay = dayValue;
          break;
        }
      }
      
      // Skip if not the target year
      if (yearLevel && currentYear !== parseInt(yearLevel)) continue;
      
      // Parse time slots (format: HH:MM-HH:MM)
      const timeMatch = line.match(/(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})/);
      if (timeMatch && currentDay !== null) {
        const startTime = `${timeMatch[1].padStart(2, '0')}:${timeMatch[2]}`;
        const endTime = `${timeMatch[3].padStart(2, '0')}:${timeMatch[4]}`;
        
        // Split line into columns
        const parts = line.split(/\s{2,}/); // Split by multiple spaces
        
        // Look for course codes in the line
        const courseRegex = /([A-Z]{2,4})\s+(\d{3})/g;
        let match;
        const coursesInLine = [];
        
        while ((match = courseRegex.exec(line)) !== null) {
          const courseCode = `${match[1]} ${match[2]}`;
          coursesInLine.push({
            code: courseCode,
            position: match.index
          });
        }
        
        // Extract location/room information
        const roomRegex = /([A-Z0-9\-]+)\s+([\w\-]+)/;
        const locationMatches = line.match(roomRegex);
        
        // Extract instructor names (usually capitalized words after location)
        const instructorRegex = /([A-Z]\.\s*[A-Z][a-z]+\s*[A-Z]*[a-z]*)/g;
        const instructors = [];
        let instMatch;
        while ((instMatch = instructorRegex.exec(line)) !== null) {
          instructors.push(instMatch[1].trim());
        }
        
        // Process each course found
        coursesInLine.forEach((courseInfo, index) => {
          // Check if this course belongs to target program
          const coursePrefix = courseInfo.code.substring(0, 2);
          const programPrefixes = {
            'AEROSPACE': ['AE', 'AERO'],
            'CHEMICAL': ['CHE', 'CHEM'],
            'CIVIL': ['CE'],
            'COMPUTER': ['COE', 'COMP'],
            'ELECTRICAL': ['EE'],
            'GEOMATIC': ['GE'],
            'MECHANICAL': ['ME'],
            'MATERIALS': ['MSE'],
            'PETROLEUM': ['PE', 'PCE']
          };
          
          // Check if course belongs to target program or is a common course
          const isTargetCourse = targetProgram === 'ALL' || 
            programPrefixes[targetProgram]?.includes(coursePrefix) ||
            ['MATH', 'ENGL', 'ECON', 'FC', 'STAT', 'TE'].includes(coursePrefix); // Common courses
          
          if (isTargetCourse) {
            // Extract course name (usually follows course code)
            const codeIndex = line.indexOf(courseInfo.code);
            const afterCode = line.substring(codeIndex + courseInfo.code.length, codeIndex + 100);
            const nameMatch = afterCode.match(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/);
            const courseName = nameMatch ? nameMatch[1].trim() : courseInfo.code;
            
            // Determine building and room
            let building = '';
            let roomNumber = '';
            if (locationMatches) {
              building = locationMatches[1];
              roomNumber = locationMatches[2] || '';
            }
            
            // If location contains specific keywords
            const locationKeywords = line.match(/(LAB|PRACTICALS|PROJECT|NEB-\w+|FOSS\s+\w+|PB\d+|VSLA|VCR|ECR|ENG\s+AUDIT)/);
            if (locationKeywords) {
              const loc = locationKeywords[1];
              if (loc.includes('-')) {
                const [bldg, room] = loc.split('-');
                building = bldg;
                roomNumber = room;
              } else {
                building = loc;
              }
            }
            
            courses.push({
              course_code: courseInfo.code,
              course_name: courseName,
              day_of_week: currentDay,
              start_time: startTime,
              end_time: endTime,
              building: building || 'TBD',
              room_number: roomNumber || '',
              instructor: instructors[index] || instructors[0] || 'Staff',
              year_level: currentYear || yearLevel
            });
          }
        });
      }
    }
    
    // Remove duplicates
    const uniqueCourses = courses.filter((course, index, self) =>
      index === self.findIndex(c => 
        c.course_code === course.course_code &&
        c.day_of_week === course.day_of_week &&
        c.start_time === course.start_time
      )
    );
    
    return {
      success: true,
      courses: uniqueCourses,
      totalFound: uniqueCourses.length,
      yearLevel: currentYear || yearLevel
    };
    
  } catch (error) {
    console.error('PDF parsing error:', error);
    return {
      success: false,
      error: error.message,
      courses: []
    };
  }
}

// Add this route to your server.js
function addPDFParsingRoute(app, pool) {
  app.post('/api/parse-timetable-pdf', authMiddleware, upload.single('pdf'), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ success: false, error: 'No PDF file uploaded' });
      }
      
      const { program, yearLevel } = req.body;
      
      if (!program) {
        return res.status(400).json({ success: false, error: 'Program not specified' });
      }
      
      // Parse the PDF
      const result = await parseTimetablePDF(req.file.buffer, program, yearLevel);
      
      if (result.success) {
        res.json({
          success: true,
          courses: result.courses,
          count: result.totalFound,
          yearLevel: result.yearLevel
        });
      } else {
        res.status(500).json({
          success: false,
          error: result.error || 'Failed to parse PDF'
        });
      }
      
    } catch (error) {
      console.error('PDF upload error:', error);
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  });
}

module.exports = {
  parseTimetablePDF,
  addPDFParsingRoute,
  upload
};
