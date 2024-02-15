// Assuming you have the necessary dependencies installed
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/testing', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
const User = mongoose.model('User', {
    username: String,
    password: String,
    role: String, // Admin, Supervisor, Worker
});

// Default Admin user creation
const createDefaultAdmin = async () => {
    const adminExists = await User.exists({ username: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('adminpassword', 10);
        await User.create({ username: 'admin', password: hashedPassword, role: 'Admin' });
        console.log('Default Admin user created.');
    }
};
createDefaultAdmin();

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // const user = await User.findOne({ username });

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.status(401).json({ message: 'Incorrect password' });
    }

    const token = jwt.sign({ username: user.username, role: user.role }, 'secretkey');
    res.json({ token });
});

// Middleware to verify token and role
const verifyTokenAndRole = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Token not provided' });

    jwt.verify(token, 'secretkey', (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });

        req.user = decoded;
        next();
    });
};

// Example endpoint accessible only to Admin
app.get('/admin/dashboard', verifyTokenAndRole, (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Access forbidden' });
    }
    res.json({ message: 'Welcome to Admin dashboard' });
});

// Example endpoint accessible to Supervisor
app.get('/supervisor/dashboard', verifyTokenAndRole, (req, res) => {
    if (req.user.role !== 'Supervisor') {
        return res.status(403).json({ message: 'Access forbidden' });
    }
    res.json({ message: 'Welcome to Supervisor dashboard' });
});

// Example endpoint accessible to Worker
app.get('/worker/dashboard', verifyTokenAndRole, (req, res) => {
    if (req.user.role !== 'Worker') {
        return res.status(403).json({ message: 'Access forbidden' });
    }
    res.json({ message: 'Welcome to Worker dashboard' });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
