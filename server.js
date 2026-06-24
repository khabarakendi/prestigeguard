require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve frontend static files from the public directory 
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
// ==========================================
// 1. Database Schemas & Models
// ==========================================
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});
const User = mongoose.model('User', userSchema);

const articleSchema = new mongoose.Schema({
    articleNumber: {
        type: Number,
        unique: true
    },
    title: { type: String, required: true },

    slug: {
        type: String,
        required: true,
        unique: true
    },

    category: { type: String, required: true },

    icon: {
        type: String,
        default: 'file-text'
    },

    excerpt: {
        type: String,
        required: true
    },

    bodyText: {
        type: String,
        required: true
    },

    date: {
        type: String,
        required: true
    }

}, { timestamps: true });
const Article = mongoose.model('Article', articleSchema);

// ==========================================
// 2. Database Connection & Admin Seeding
// ==========================================
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
    console.error('❌ FATAL ERROR: MONGO_URI is not defined in .env');
    process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || 'development_fallback_secret_change_in_production';

mongoose.connect(MONGO_URI)
    .then(async () => {
        console.log('✅ Connected to MongoDB Atlas successfully!');
        
        // Seed default admin account if none exists
        const adminEmail = "admin@prestigeguard.com";
        const adminExists = await User.findOne({ email: adminEmail });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_DEFAULT_PASSWORD || "ZokLok@2011", 10);
            await User.create({
                email: adminEmail,
                password: hashedPassword,
                role: 'admin'
            });
            console.log('👤 Default admin account seeded.');
        }
    })
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ==========================================
// 3. Authentication Middlewares
// ==========================================
const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access Denied: Token Missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Access Denied: Invalid Token' });
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ message: 'Access Denied: Admin Privileges Required' });
    }
};

// ==========================================
// 4. API Endpoints
// ==========================================

// Admin Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, role: user.role, email: user.email });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login' });
    }
});

// Fetch All Articles
app.get('/api/articles', async (req, res) => {
    try {
        const articles = await Article.find().sort({ createdAt: -1 });
        res.json(articles);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch articles' });
    }
});

app.get("/ping", (req, res) => {
    res.status(200).send("OK");
});

// Create New Article (Admin Only)
app.post('/api/articles', authenticate, requireAdmin, async (req, res) => {

    try {

        
        const lastArticle = await Article
            .find({ articleNumber: { $exists: true, $ne: null } })
            .sort({ articleNumber: -1 })
            .limit(1);

        const lastNumber = Number(lastArticle?.[0]?.articleNumber);

        const nextNumber = Number.isFinite(lastNumber)
            ? lastNumber + 1
            : 1;

        const newArticle = await Article.create({
            articleNumber: Number(nextNumber),
            slug: String(nextNumber),

            title: req.body.title,
            category: req.body.category,
            icon: req.body.icon,
            excerpt: req.body.excerpt,
            bodyText: req.body.bodyText,
            date: req.body.date
        });


        res.status(201).json(newArticle);

    } catch (error) {
            console.error("CREATE ARTICLE ERROR:", error);
            return res.status(500).json({
                message: error.message
            });
        }

});

// Delete Article (Admin Only)
app.delete('/api/articles/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        await Article.findByIdAndDelete(req.params.id);
        res.json({ message: 'Article removed successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete article' });
    }
});

app.get('/articles/:slug', (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            'public',
            'articles.html'
        )
    );

});

// Fallback routing: Route all unhandled requests to index.html
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Dynamic cluster port binding
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
