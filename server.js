// server.js
import express from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";




const app = express();
const PORT = 5001;


const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Jaimatadi05@",
  database: "test",
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to the database:", err);
  } else {
    console.log("Connected to the database");
  }
});



app.use(express.json());
app.use(cors({ origin: "http://localhost:3000" }));
app.use(cookieParser());

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

app.get("/adminlogin", (req, res) => {
  const q = "SELECT * FROM admincredentials;";
  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

app.post('/UserLogin', (req, res) => {
  const { Username, Password } = req.body;

  db.query('SELECT * FROM usercredentials WHERE Username = ?', [Username], async (err, results) => {
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

    const token = jwt.sign({ id: user.ID, username: user.Username }, SECRET_KEY, {
      expiresIn: '1h',
    });

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 3600000, // 1 hour in milliseconds
    }).json({ success: true, message: 'User logged in successfully.' });
  });
});

app.post('/AdminLogin', (req, res) => {
  const { Username, Password } = req.body;

  db.query('SELECT * FROM admincredentials WHERE Username = ?', [Username], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Internal server error.' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Username or password is incorrect.' });
    }

    const admin = results[0];

    const isPasswordValid = await bcrypt.compare(Password, admin.Password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Username or password is incorrect.' });
    }

    const token = jwt.sign({ id: admin.ID, username: admin.Username }, SECRET_KEY, {
      expiresIn: '1h',
    });

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 3600000, // 1 hour in milliseconds
    }).json({ success: true, message: 'Admin logged in successfully.' });
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token').json({ success: true, message: 'Logged out successfully.' });
});

// Admin Sign Up Endpoint
app.post('/adminSignup', (req, res) => {
  const { Username, Password } = req.body;

  db.query('SELECT * FROM admincredentials WHERE Username = ?', [Username], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Internal server error.' });
    }

    if (results.length > 0) {
      return res.status(409).json({ message: 'Username already exists.' });
    }

    try {
      const hashedPassword = await bcrypt.hash(Password, SALT_ROUNDS);
      db.query('INSERT INTO admincredentials (Username, Password) VALUES (?, ?)', [Username, hashedPassword], (err, result) => {
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

// User Sign Up Endpoint
app.post('/userSignup', (req, res) => {
  const { Username, Password } = req.body;

  db.query('SELECT * FROM usercredentials WHERE Username = ?', [Username], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Internal server error.' });
    }

    if (results.length > 0) {
      return res.status(409).json({ message: 'Username already exists.' });
    }

    try {
      const hashedPassword = await bcrypt.hash(Password, SALT_ROUNDS);
      db.query('INSERT INTO usercredentials (Username, Password) VALUES (?, ?)', [Username, hashedPassword], (err, result) => {
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

app.get("/tickets", (req, res) => {
  const q = "SELECT * FROM tickets;";
  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

app.post("/tickets", (req, res) => {
  const q =
    "INSERT INTO tickets (`Date`, `Status`, `Department`, `Category`, `Priority`, `Summary`, `Description`, `Screenshots`) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
  const values = [
    req.body.Date,
    req.body.Status,
    req.body.Department,
    req.body.Category,
    req.body.Priority,
    req.body.Summary,
    req.body.Description,
    req.body.Screenshots,
  ];
  db.query(q, values, (err, data) => {
    if (err) return res.json(err);
    return res.json("Ticket has been generated");
  });
});

app.get("/search", (req, res) => {
  const { TicketID, Date, Department, Status, Category, Priority } = req.query;
  let q = "SELECT * FROM tickets WHERE 1=1";

  if (TicketID) {
    q += ` AND TicketID = '${TicketID}'`;
  }

  if (Date) {
    q += ` AND Date = '${Date}'`;
  }

  if (Department) {
    q += ` AND Department = '${Department}'`;
  }

  if (Status) {
    q += ` AND Status = '${Status}'`;
  }


  if (Priority) {
    q += ` AND Priority = '${Priority}'`;
  }

  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

// Update an existing ticket
app.put("/tickets/:TicketID", (req, res) => {
  const TicketID = req.params.TicketID;
  const {
    
    Status,
    Department,
    Category,
    Priority,
    Summary,
    Description,
  } = req.body;

  const q =
    "UPDATE tickets SET Status=?, Department=?, Category=?, Priority=?, Summary=?, Description=? WHERE TicketID=?";
  const values = [
   
    Status,
    Department,
    Category,
    Priority,
    Summary,
    Description,
  ];

  db.query(q, [...values,TicketID], (err, data) => {
    if (err) {
      return res.status(500).json({ message: "Failed to update ticket." });
    }
    return res.json({ success: true, message: "Ticket updated successfully." });
  });
});

app.get("/tickets/:TicketID", (req, res) => {
  const TicketID = req.params.TicketID;
  const q = "SELECT * FROM tickets WHERE TicketID = ?";
  
  db.query(q, [TicketID], (err, data) => {
    if (err) {
      console.error("Error fetching ticket:", err);
      return res.status(500).json({ success: false, message: "Internal server error." });
    }

    if (data.length === 0) {
      return res.status(404).json({ success: false, message: "Ticket not found." });
    }

    const ticket = data[0];
    return res.json({ success: true, ticket });
  });
});

app.delete("/tickets/:TicketID", (req,res)=>{
  const TicketID = req.params.TicketID;
  const q = "DELETE FROM tickets WHERE TicketID = ?"
  db.query(q, [TicketID], (err, data) => {
    if (err) {
      return res.status(500).json({ message: "Book not deleted " });
    }
    return res.json({ success: true, message: "Book has been deleted successfully" });
  });
}
)


  
 


app.listen(process.env.PORT || PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
