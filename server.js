import express from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";


const app = express();
const PORT = 5001;

app.use(express.json());
app.use(express.static('public'));
app.use(cors(
  {
      origin: ["http://localhost:3000"],
      methods: ["POST", "GET", "PUT", "DELETE"],
      credentials: true
  }
));
app.use(cookieParser());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Admin@09876",
  database: "test",
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to the database:", err);
  } else {
    console.log("Connected to the database");
  }
});


const SECRET_KEY = '5c108250980f6547724b668927288b75';
const SALT_ROUNDS = 10;

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(403).json({ message: 'No token provided.' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(500).json({ message: 'Failed to authenticate token.' });
    req.userId = decoded.id;
    next();
  });
};


//login end point
app.post('/login', (req, res) => {
    const { Username, Password } = req.body;
  
    db.query('SELECT * FROM credentials WHERE Username = ?', [Username], async (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Internal server error.' });
      }
  
      if (results.length === 0) {
        return res.status(401).json({ message: 'Username or password is incorrect.' });
      }
  
      const user = results[0];
  
      const isPasswordValid = await bcrypt.compare(Password, user.Password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Username or password is incorrect.' });
      }
  
      const token = jwt.sign({ id: user.ID, username: user.Username, role: user.Role }, SECRET_KEY, {
        expiresIn: '1h',
      });

    res.cookie('token', token, {
        httpOnly: true,
        maxAge: 3600000, // 1 hour in milliseconds
      }).json({ success: true, message: 'Logged in successfully.',  role: user.Role });
  });
});

// Sign Up Endpoint
app.post('/Signup', (req, res) => {
  const { FullName, Email, PhoneNumber, Address, Username, Password, Role } = req.body; // Extract values from req.body

  db.query('SELECT * FROM credentials WHERE Username = ?', [Username], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Internal server error.' });
    }

    if (results.length > 0) {
      return res.status(409).json({ message: 'Username already exists.' });
    }

    try {
      const hashedPassword = await bcrypt.hash(Password, SALT_ROUNDS);
      db.query('INSERT INTO credentials (FullName, Email, PhoneNumber, Address, Username, Password, Role) VALUES (?, ?, ?, ?, ?, ?, ?)', [FullName, Email, PhoneNumber, Address, Username, hashedPassword, Role], (err, result) => {
        if (err) {
          return res.status(500).json({ message: 'Failed to create admin account.' });
        }
        return res.json({ success: true, message: 'Admin account created successfully.' });
      });
    } catch (error) {
      console.error('Error during password hashing:', error);
      return res.status(500).json({ message: 'Failed to create admin account.' });
    }
  });
});


app.get("/", (req, res) => {
  res.json("hello this is the backend");
});

app.listen(process.env.PORT || PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

