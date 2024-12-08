require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const express = require('express');
const mongoose = require('mongoose');
const app = express();
const port = 3000;

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log(err));

// User model schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: String,
  password: String,
  phoneNumber: String,
});

const User = mongoose.model('User', userSchema);

// Middleware to parse JSON and urlencoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Register route
app.post('/register', async (req, res) => {
    const { firstName, lastName, email, password, phoneNumber } = req.body;
  
    // Hash the password before saving the user
    const hashedPassword = await bcrypt.hash(password, 10);
  
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword, 
      phoneNumber,
    });
  
    try {
      await newUser.save();
      res.json({ message: 'User registered successfully!' });
    } catch (err) {
      res.status(500).json({ message: 'Error registering user', error: err });
    }
  });


// Login route to authenticate users
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(400).json({ message: 'User not found' });
      }
  
      // Compare the entered password with the hashed password in the database
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Incorrect password' });
      }
  
      // Send a success response and JWT token
      const token = jwt.sign({ userId: user._id }, 'your-jwt-secret', { expiresIn: '1h' });
      res.json({ message: 'Login successful', token });
    } catch (err) {
      res.status(500).json({ message: 'Server error', error: err });
    }
  });
  



// GET route to display all users in an HTML table
app.get('/users', async (req, res) => {
    try {
      const users = await User.find();
      let userTable = `
        <html>
          <head>
            <style>
              body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
              }
              table {
                width: 80%;
                border-collapse: collapse;
                margin-top: 30px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                background-color: white;
              }
              th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
              }
              th {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
              }
              tr:hover {
                background-color: #f1f1f1;
              }
              td {
                color: #333;
              }
              table tr:last-child td {
                border-bottom: none;
              }
            </style>
          </head>
          <body>
            <table>
              <tr>
                <th>First Name</th>
                <th>Last Name</th>
                <th>Email</th>
                <th>Phone Number</th>
              </tr>
      `;
  
      users.forEach((user) => {
        userTable += `
          <tr>
            <td>${user.firstName}</td>
            <td>${user.lastName}</td>
            <td>${user.email}</td>
            <td>${user.phoneNumber}</td>
          </tr>
        `;
      });
  
      userTable += `
            </table>
          </body>
        </html>
      `;
  
      res.send(userTable); 
    } catch (err) {
      res.status(500).send('Error fetching users');
    }
  });
  

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
