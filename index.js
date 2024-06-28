// server.js

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
// const mysql = require('mysql2/promise');
// const { sendResetEmail } = require('./mailer');

const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser')
const salt = 1;

const app = express();
const port = 5000;

app.use(cors({
  origin: ["http://localhost:5173"],
  // methods: ["POST", "GET"],
  credentials: true
}

));
app.use(bodyParser.json());
app.use(cookieParser());
// MySQL connection setup
const conn = mysql.createConnection({
  host: 'localhost',
  user: 'abstruct',
  password: 'password',
  database: 'university'
});

conn.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
});

// reset password
// <<<<<<<<<<<----------------->>>>>>>>>>>>>


const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'rokon2514@student.nstu.edu.bd',
    pass: 'dzya lxxp qtvf ofry' // Use the App Password generated
  }
});

const sendResetEmail = (email, token) => {
  console.log(`Sending email to: ${email}, with token: ${token}`);
  const resetLink = `http://localhost:5173/reset-password?token=${token}`;
  const mailOptions = {
    from: 'rokon2514@student.nstu.edu.bd',
    to: email,
    subject: 'Password Reset',
    html: `<p>To reset your password, please click the link below:</p>
           <a href="${resetLink}">Reset Password</a>`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

app.post('/auth/request-reset', (req, res) => {
  const { email } = req.body;
  const sql = 'SELECT * FROM users WHERE user_email = ?';

  conn.query(sql, [email], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      const user = results[0];
      const token = crypto.randomBytes(20).toString('hex');
      const tokenExpiry = Date.now() + 3600000; // 1 hour from now

      const updateSql = 'UPDATE users SET reset_password_token = ?, reset_password_expires = ? WHERE user_email = ?';
      conn.query(updateSql, [token, tokenExpiry, email], (err, result) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }

        sendResetEmail(email, token);
        res.json({ message: 'Reset email sent' });
      });
    } else {
      res.status(404).json({ message: 'Email not found' });
    }
  });
});

app.post('/auth/reset-password', (req, res) => {
  const { token, newPassword } = req.body;
  const sql = 'SELECT * FROM users WHERE reset_password_token = ? AND reset_password_expires > ?';

  conn.query(sql, [token, Date.now()], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      const user = results[0];

      bcrypt.hash(newPassword.toString(), salt, (err, hash) => {
        if (err) return res.json({ error: "Error hashing password" });

        const updateSql = 'UPDATE users SET user_password = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE user_email = ?';
        conn.query(updateSql, [hash, user.user_email], (err, result) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          res.json({ message: 'Password has been reset' });
        });
      });
    } else {
      res.status(400).json({ message: 'Invalid or expired token' });
    }
  });
});
// <<<<<<<<<<<<<<<<<<<<<<_______________________>>>>>>>>>>>>>>>>>>>>



// Register
app.post('/auth/register', (req, res) => {
  const sql = "INSERT INTO users (`user_name`, `user_email`,`user_mobile`,`user_type`,`user_password`, `user_image`) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: "Error for hashing password" });
    // console.log(req.body)
    console.log(hash)
    const values = [
      req.body.name,
      req.body.email,
      req.body.mobile,
      req.body.userType,
      hash,
      req.body.image
    ]
    conn.query(sql, [values], (err, result) => {
      if (err) return res.json(err);
      return res.json({ Status: "Success" });
    })
  })

})
// Login route
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE user_email = ?';


  conn.query(sql, [email], (err, results) => {

    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      const user = results[0];


      bcrypt.compare(password, user.user_password, (err, response) => {

        if (err) {

          console.error('Password compare error:', err);
          return res.status(500).json({ error: 'Password compare error' });
        }

        if (response) {

          const token = jwt.sign(
            { email: user.user_email, userType: user.user_type },
            '5dedg788dg88wdgwdgd8w8fge8f',
            { expiresIn: '1h' }
          );
          res.cookie('token', token);
          return res.json({ message: 'Login successful', user: user, userType: user.user_type, token: token });
        } else {
          return res.status(401).json({ message: 'Invalid email or password' });
        }
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  });
});

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.json({ Error: "you are not authenticated" });
  } else {
    jwt.verify(token, "5dedg788dg88wdgwdgd8w8fge8f", (err, decoded) => {
      if (err) {
        return res.json({ Error: "token is not okay" });
      } else {
        req.userType = decoded.userType;

        // Set userType in the request object
        next();
      }
    })
  }
}



app.get('/dashboard', verifyToken, (req, res) => {
  // At this point, the token has already been verified in the verifyToken middleware
  // So, you can directly access the decoded token data from req.name or req.userType

  // Check user role and return appropriate dashboard data
  if (req.userType === 'student') {
    // Fetch student dashboard data from database
    res.json({ message: 'Access granted - Student Dashboard', data: 'student_dashboard_data', status: 'Success' });
  } else if (req.userType === 'teacher') {
    // Fetch teacher dashboard data from database
    res.json({ message: 'Access granted - Teacher Dashboard', data: 'teacher_dashboard_data', status: 'Success' });
  } else if (req.userType === 'chairman') {
    // Fetch chairman dashboard data from database
    res.json({ message: 'Access granted - Chairman Dashboard', data: 'chairman_dashboard_data', status: 'Success' });
  } else if (req.userType === 'coordinator') {
    // Fetch coordinator dashboard data from database
    res.json({ message: 'Access granted - Coordinator Dashboard', data: 'coordinator_dashboard_data', status: 'Success' });
  } else if (req.userType === 'provost') {
    // Fetch provost dashboard data from database
    res.json({ message: 'Access granted - Provost Dashboard', data: 'provost_dashboard_data', status: 'Success' });
  } else if (req.userType === 'register office') {
    // Fetch register office dashboard data from database
    res.json({ message: 'Access granted - Register Office Dashboard', data: 'register_office_dashboard_data', status: 'Success' });
  } else {
    res.status(403).json({ message: 'Unauthorized: Access denied' });
  }
});
// API endpoint to fetch courses based on year and term
app.get('/api/courses', (req, res) => {
  const { year, term } = req.query;
  const courseLevel = `${year}-${term}`;

  const query = 'SELECT course_id,course_name, course_code,teacher_id,course_level FROM courses WHERE course_level = ?';
  conn.query(query, [courseLevel], (err, results) => {
    if (err) {
      console.error('Error fetching courses:', err);
      res.status(500).json({ error: 'Internal server error' });
      return;
    }
    res.json(results);
  });
});

// API endpoint to fetch teachers based on department_id
app.get('/api/teachers', (req, res) => {
  const departmentId = 1; // assuming you want to fetch teachers for department_id = 1

  const query = `
    SELECT u.user_id, t.teacher_id, u.user_name AS name
    FROM users u
    INNER JOIN teachers t ON u.user_id = t.user_id
    WHERE t.department_id = ?`;

  conn.query(query, [departmentId], (err, results) => {
    if (err) {
      console.error('Error fetching teachers:', err); // Log the error
      res.status(500).json({ error: 'Internal server error' });
      return;
    }
    res.json(results);
  });
});

// Update courses
app.post('/api/update-courses', (req, res) => {
  const { updates } = req.body;

  updates.forEach(update => {
    const query = 'UPDATE courses SET teacher_id = ? WHERE course_id = ?';
    conn.query(query, [update.teacher_id, update.course_id], (error) => {
      if (error) {
        console.error('Error updating course:', error);
      }
    });
  });

  res.status(200).json({ message: 'Courses updated successfully' });
});


// unique teacer 
app.get('/api/unique_teacher', (req, res) => {
  const userId = req.query.userId;

  conn.query('SELECT * FROM teachers WHERE user_id = ?', [userId], (error, results) => {
    if (error) {
      console.error('Database error:', error);
      return res.status(500).json({ error: 'Database error', details: error.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Teacher not found' });
    }
    res.json(results[0]);
  });
});
// unique student 
app.get('/api/unique_student', (req, res) => {
  const { userId } = req.query;

  const sql = `
      SELECT student_id, level
      FROM students
      WHERE user_id = ?
  `;

  conn.query(sql, [userId], (err, result) => {
      if (err) {
          console.error('Error fetching student data:', err);
          res.status(500).json({ error: 'Error fetching student data' });
          return;
      }
      
      // Assuming only one student should match the user_id
      if (result.length > 0) {
          res.json(result[0]); // Send the first matching student data
      } else {
          res.status(404).json({ error: 'Student not found' });
      }
  });
});
// Fetch courses data based on teacher ID
app.get('/api/unique_courses', (req, res) => {
  const teacherId = req.query.teacherId;

  conn.query('SELECT * FROM courses WHERE teacher_id = ?', [teacherId], (error, results) => {
    if (error) {
      console.error('Database error:', error);
      return res.status(500).json({ error: 'Database error', details: error.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'No courses found for this teacher' });
    }
    res.json(results);
  });
});
// fetc attendence student 
app.get('/api/getStudents', (req, res) => {
  const { course_level } = req.query;
  // console.log('Received course_level:', course_level);

  let batch;

  if (course_level === '4-2') {
    batch = 14;
  } else if (course_level === '3-2') {
    batch = 15;
  } else {
    return res.status(400).send('Invalid course level');
  }

  const query = `
  SELECT  s.student_id,s.roll, u.user_name
    FROM students s
    JOIN users u ON s.user_id = u.user_id
    WHERE s.batch = ?
    ORDER BY s.roll
  `;
  // console.log('Executing query:', query, 'with params:', [course_level, batch]);

  conn.query(query, [batch], (error, results) => {
    if (error) {
      console.error('Database query failed:', error);
      return res.status(500).json({ error: 'Database query failed' });
    }
    res.json(results);
  });
});

// take student attendence 
app.post('/api/attendances', (req, res) => {
  const attendances = req.body;
  const sql = 'INSERT INTO attendances (student_id, teacher_id, course_id, date, attendance_status) VALUES ?';
  const values = attendances.map(attendance => [
    attendance.student_id,
    attendance.teacher_id,
    attendance.course_id,
    attendance.date,
    attendance.attendance_status
  ]);

  conn.query(sql, [values], (err, result) => {
    if (err) throw err;
    res.send('Attendance records inserted');
  });
});

// view attendance 
// Check evaluation endpoint
app.get('/api/check-evaluation', (req, res) => {
  const { courseId, studentId } = req.query;

  // SQL query to check evaluation
  const sql = 'SELECT COUNT(*) as count FROM evaluations WHERE course_id = ? AND student_id = ?';
  conn.query(sql, [courseId, studentId], (err, results, fields) => {
    if (err) {
      console.error('Error checking evaluation:', err);
      res.status(500).json({ error: 'Database error' });
      return;
    }
    const count = results[0].count;
    if (count > 0) {
      res.json({ submitted: true });
    } else {
      res.json({ submitted: false });
    }
  });
});


// Evaluate course endpoint
app.post('/api/evaluate-course', (req, res) => {
  const { courseId, teacherid, evaluationScore, evaluationDate,student } = req.body;

  // SQL query to insert evaluation
  const sql = 'INSERT INTO evaluations (course_id, teacher_id, evaluation_score, evaluation_date,student_id) VALUES (?, ?, ?, ?,?)';
  conn.query(sql, [courseId, teacherid, evaluationScore, evaluationDate,student], (err, results, fields) => {
    if (err) {
      console.error('Error inserting evaluation:', err);
      res.status(500).json({ error: 'Database error' });
      return;
    }

    res.send('Evaluation submitted successfully');
  });
});


app.get('/api/evaluation_score', (req, res) => {
  const { courseId } = req.query;
  conn.query('SELECT evaluation_score, evaluation_date FROM evaluations WHERE course_id = ?', [courseId], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json(rows);
    }
  });
});
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
