const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = "mongodb+srv://cyb:cyb@cyb.amydmvv.mongodb.net/cyber?appName=cyb";

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// MongoDB Connection
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// Schema
const linkSchema = new mongoose.Schema({
    url: { type: String, required: true, unique: true },
    reason: String,
    source: String,
    reportCount: { type: Number, default: 0 },
    lastScanned: { type: Date, default: Date.now }
});

const Link = mongoose.model('Link', linkSchema);

// API Routes

// 1. Get all scanned links
app.get('/api/links', async (req, res) => {
    try {
        const links = await Link.find().sort({ lastScanned: -1 });
        res.json(links);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Register/Update a scanned URL (from extension)
app.post('/api/scan', async (req, res) => {
    const { url, reason, source } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    try {
        let link = await Link.findOne({ url });
        if (link) {
            link.reason = reason || link.reason;
            link.source = source || link.source;
            link.lastScanned = Date.now();
            await link.save();
        } else {
            link = new Link({ url, reason, source });
            await link.save();
        }
        res.json(link);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Increment report count
app.post('/api/report', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    try {
        const link = await Link.findOne({ url });
        if (!link) return res.status(404).json({ error: 'Link not found' });

        link.reportCount += 1;
        await link.save();
        res.json({ success: true, reportCount: link.reportCount });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. Quick status check for extension
app.get('/api/check', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    try {
        const link = await Link.findOne({ url });
        res.json({ 
            blocked: link ? link.reportCount > 5 : false,
            reportCount: link ? link.reportCount : 0 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Serve Dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
