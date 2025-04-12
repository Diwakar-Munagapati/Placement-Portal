const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configure CORS properly for production
app.use(cors({
  origin: true, // Allow the same origin
  credentials: true // Allow cookies to be sent
}));

// Set up session with more secure options
app.use(
  session({
    secret: "yourKey", // Use a strong random secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      httpOnly: true, // Prevent JavaScript access to cookies
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  })
);

// Custom middleware to override default index.html behavior
app.use((req, res, next) => {
  if (req.path === '/' || req.path === '/index.html') {
    res.sendFile(path.join(__dirname, "public", "home.html"));
  } else {
    next();
  }
});

// Static files middleware comes after our custom middleware
app.use(express.static("public"));

const db = mysql.createConnection({  
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT 
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connected to MYSQL Database");
});

// Authentication middleware to check if user is logged in
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ message: "Please log in to continue" });
  }
};

// Routes
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.get("/jobs", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// REGISTER ROUTE (Modified to handle all user fields)
app.post("/register", (req, res) => {
  const { username, password, name, Enrollment_no, Email, Phone_no } = req.body;

  // Check if user already exists
  db.query("SELECT * FROM users WHERE username = ? OR Enrollment_no = ?", 
    [username, Enrollment_no], 
    async (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Database error" });
      }

      if (result.length > 0) {
        return res.status(400).json({ message: "Username or Enrollment number already exists" });
      }

      try {
        // Hash the password for better security
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert new user into database with all fields
        db.query(
          "INSERT INTO users (username, password, name, Enrollment_no, Email, Phone_no) VALUES (?, ?, ?, ?, ?, ?)", 
          [username, hashedPassword, name, Enrollment_no, Email, Phone_no], 
          (err, result) => {
            if (err) {
              console.error(err);
              return res.status(500).json({ message: "Database error" });
            }
            res.status(201).json({ message: "User registered successfully" });
          }
        );
      } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Error during registration" });
      }
  });
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.query("SELECT * FROM users WHERE username = ?", [username], async (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }

    if (result.length === 0) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const user = result[0];

    try {
      // Compare with bcrypt if you're using hashed passwords
      // If not using hashed passwords yet, keep the direct comparison
      let passwordMatch;
      
      if (user.password.startsWith('$2')) {
        // This is a bcrypt hash
        passwordMatch = await bcrypt.compare(password, user.password);
      } else {
        // This is a plain text password (for backward compatibility)
        passwordMatch = (password === user.password);
      }

      if (passwordMatch) {
        req.session.user = user;
        return res.status(200).json({ 
          message: "Login successful", 
          redirect: "home-1.html",
          userId: user.id // Send user ID to client for storage
        });
      } else {
        return res.status(401).json({ message: "Invalid username or password" });
      }
    } catch (error) {
      console.error(error);
      return res.status(500).json({ message: "Error during login" });
    }
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Logout failed" });
    }
    res.clearCookie("connect.sid"); // Clear session cookie
    return res.status(200).json({ message: "Logged out successfully" });
  });
});

// Job related endpoints
app.get("/api/jobs1", (req, res) => {
  const query = "SELECT * FROM job1 ORDER BY id DESC";
  
  db.query(query, (error, jobList) => {
    if (error) {
      console.error("Error fetching jobs from job1:", error);
      return res.status(500).json({ message: "Database error" });
    }
    res.status(200).json(jobList);
  });
});

app.get("/api/jobs1/:id", (req, res) => {
  const jobId = req.params.id;
  const query = "SELECT * FROM job1 WHERE id = ?";

  db.query(query, [jobId], (error, jobData) => {
    if (error) {
      console.error("Error fetching job from job1:", error);
      return res.status(500).json({ message: "Database error" });
    }
    if (jobData.length === 0) {
      return res.status(404).json({ message: "Job not found" });
    }
    res.status(200).json(jobData[0]);
  });
});

app.get("/api/jobs2", (req, res) => {
  const query = "SELECT * FROM job2 ORDER BY id DESC";
  
  db.query(query, (error, jobList) => {
    if (error) {
      console.error("Error fetching jobs from job2:", error);
      return res.status(500).json({ message: "Database error" });
    }
    res.status(200).json(jobList);
  });
});

app.get("/api/jobs2/:id", (req, res) => {
  const jobId = req.params.id;
  const query = "SELECT * FROM job2 WHERE id = ?";

  db.query(query, [jobId], (error, jobData) => {
    if (error) {
      console.error("Error fetching job from job2:", error);
      return res.status(500).json({ message: "Database error" });
    }
    if (jobData.length === 0) {
      return res.status(404).json({ message: "Job not found" });
    }
    res.status(200).json(jobData[0]);
  });
});

// Create job application table if it doesn't exist
db.query(`
  CREATE TABLE IF NOT EXISTS user_job_applications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    job_table VARCHAR(10) NOT NULL,
    job_id INT NOT NULL,
    application_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending',
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY (user_id, job_table, job_id)
  )
`, (err) => {
  if (err) {
    console.error("Error creating user_job_applications table:", err);
  } else {
    console.log("user_job_applications table ready");
  }
});



// POST endpoint to handle job applications
app.post("/api/apply", isAuthenticated, (req, res) => {
  const userId = req.session.user.id;
  const { jobId, jobTable } = req.body;
  
  // Validate input
  if (!jobId || !jobTable) {
    return res.status(400).json({
      success: false,
      message: 'Job ID and Job Table are required'
    });
  }
  
  // Validate job table name to prevent SQL injection
  const validTables = ['job1', 'job2', 'job3', 'job4', 'job5'];
  if (!validTables.includes(jobTable)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid job table'
    });
  }

  // Check if job exists in the specified table
  db.query(`SELECT id FROM ${jobTable} WHERE id = ?`, [jobId], (err, jobResult) => {
    if (err) {
      console.error("Error checking job existence:", err);
      return res.status(500).json({
        success: false,
        message: "Database error checking job"
      });
    }
    
    if (jobResult.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }
    
    // Check if user has already applied for this job
    db.query(
      'SELECT id FROM user_job_applications WHERE user_id = ? AND job_table = ? AND job_id = ?',
      [userId, jobTable, jobId],
      (err, applicationResult) => {
        if (err) {
          console.error("Error checking existing application:", err);
          return res.status(500).json({
            success: false,
            message: "Database error checking application"
          });
        }
        
        if (applicationResult.length > 0) {
          return res.status(409).json({
            success: false,
            message: 'You have already applied for this job'
          });
        }
        
        // Insert new application
        db.query(
          'INSERT INTO user_job_applications (user_id, job_table, job_id) VALUES (?, ?, ?)',
          [userId, jobTable, jobId],
          (err, result) => {
            if (err) {
              console.error("Error inserting application:", err);
              return res.status(500).json({
                success: false,
                message: "Database error inserting application"
              });
            }
            
            // Update the name field from the users table
            db.query(`
              UPDATE user_job_applications j
              JOIN users u ON j.user_id = u.id
              SET j.name = u.name
              WHERE j.id = ?
            `, [result.insertId], (err) => {
              if (err) {
                console.error("Error updating application name:", err);
                // Continue despite error - name update is not critical
              }
              
              // Try to update application count in the jobs table if that column exists
              db.query(
                `UPDATE ${jobTable} SET applications = applications + 1 WHERE id = ?`,
                [jobId],
                (err) => {
                  if (err) {
                    console.warn(`Could not update applications count in ${jobTable}:`, err);
                    // We don't need to fail if this update fails
                  }
                  
                  res.status(201).json({
                    success: true,
                    message: 'Application submitted successfully',
                    applicationId: result.insertId
                  });
                }
              );
            });
          }
        );
      }
    );
  });
});

// GET endpoint to check if a user has already applied for a job
app.get("/api/application-status", (req, res) => {
  // Get user ID from query params or session
  const userId = req.query.userId || (req.session.user ? req.session.user.id : null);
  const { jobId, jobTable } = req.query;
  
  if (!userId) {
    return res.status(200).json({
      hasApplied: false,
      message: 'User not logged in'
    });
  }
  
  if (!jobId || !jobTable) {
    return res.status(400).json({
      hasApplied: false,
      message: 'Job ID and Job Table are required'
    });
  }
  
  // Validate job table name
  const validTables = ['job1', 'job2', 'job3', 'job4', 'job5'];
  if (!validTables.includes(jobTable)) {
    return res.status(400).json({
      hasApplied: false,
      message: 'Invalid job table'
    });
  }

  db.query(
    'SELECT id FROM user_job_applications WHERE user_id = ? AND job_table = ? AND job_id = ?',
    [userId, jobTable, jobId],
    (err, applications) => {
      if (err) {
        console.error("Error checking application status:", err);
        return res.status(500).json({
          hasApplied: false,
          message: 'Error checking application status'
        });
      }
      
      res.json({
        hasApplied: applications.length > 0
      });
    }
  );
});

// GET endpoint to get all applications for the current user
app.get("/api/my-applications", isAuthenticated, (req, res) => {
  const userId = req.session.user.id;
  
  db.query(
    `SELECT a.*, 
      CASE
        WHEN a.job_table = 'job1' THEN j1.title
        WHEN a.job_table = 'job2' THEN j2.title
        ELSE 'Unknown'
      END AS job_title,
      CASE
        WHEN a.job_table = 'job1' THEN j1.company
        WHEN a.job_table = 'job2' THEN j2.company
        ELSE 'Unknown'
      END AS company
    FROM user_job_applications a
    LEFT JOIN job1 j1 ON a.job_table = 'job1' AND a.job_id = j1.id
    LEFT JOIN job2 j2 ON a.job_table = 'job2' AND a.job_id = j2.id
    WHERE a.user_id = ?
    ORDER BY a.application_date DESC`,
    [userId],
    (err, applications) => {
      if (err) {
        console.error("Error fetching user applications:", err);
        return res.status(500).json({
          success: false,
          message: "Database error fetching applications"
        });
      }
      
      res.json({
        success: true,
        applications: applications
      });
    }
  );
});

// Endpoint to get current user info
app.get("/api/user", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      message: "Not logged in"
    });
  }
  
  // Don't send password to client
  const { password, ...userWithoutPassword } = req.session.user;
  res.json({
    success: true,
    user: userWithoutPassword
  });
});

app.listen(3000, function () {
  console.log("SERVER STARTED ON PORT 3000");
});
