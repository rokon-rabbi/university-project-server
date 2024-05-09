// server.js

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser')
const salt = 1;

const app = express();
const port = 5000;

app.use(cors({
  origin: ["http://localhost:5173"],
  methods: ["POST", "GET"],
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


// Register
app.post('/auth/register', (req, res) => {
  const sql = "INSERT INTO users (`user_name`, `user_email`,`user_mobile`,`user_type`,`user_password`) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: "Error for hashing password" });
    // console.log(req.body)
    console.log(hash)
    const values = [
      req.body.name,
      req.body.email,
      req.body.mobile,
      req.body.userType,
      hash
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
          return res.json({ message: 'Login successful', userType: user.user_type, token: token });
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
        req.userType = decoded.userType; // Set userType in the request object
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
    res.json({ message: 'Access granted - Student Dashboard', data: 'student_dashboard_data',status:'Success' });
  } else if (req.userType === 'teacher') {
    // Fetch teacher dashboard data from database
    res.json({ message: 'Access granted - Teacher Dashboard', data: 'teacher_dashboard_data' });
  } else {
    res.status(403).json({ message: 'Unauthorized: Access denied' });
  }
});




app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
