const express = require("express");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const { OpenAI } = require("openai");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 10 * 1024 * 1024
    }
});
require("dotenv").config();

const app = express();

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        error: "Too many authentication attempts. Please try again later."
    }
});

const aiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 60,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        error: "Too many AI requests. Please try again later."
    }
});

const conversations = new Map();

const db = require("better-sqlite3")("data/ubuntu.db");

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();
db.prepare(`
  CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    conversation_id TEXT NOT NULL,
    message_id INTEGER,
    rating TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();
db.prepare(`
  CREATE TABLE IF NOT EXISTS memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    memory TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    conversation_id TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    title TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

app.use(cors());
app.use(express.json());

const openai = new OpenAI({
apiKey: process.env.OPENAI_API_KEY
});
// Conversation memory
let conversationHistory = [
  {
    role: "system",
    content: "You are Ubuntu Voice. You understand and speak Shona and English perfectly."
  }
];
app.post("/signup", authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required."
            });
        }

        const existingUser = db
            .prepare("SELECT id FROM users WHERE email = ?")
            .get(email);

        if (existingUser) {
            return res.status(409).json({
                error: "User already exists."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const result = db
            .prepare(
                "INSERT INTO users (email, password) VALUES (?, ?)"
            )
            .run(email, hashedPassword);

        res.json({
            message: "Account created successfully.",
            userId: result.lastInsertRowid
        });

    } catch (error) {
        console.error("SIGNUP ERROR:", error);

        res.status(500).json({
            error: "Could not create account."
        });
    }
});
app.post("/login", authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required."
            });
        }

        const user = db
            .prepare("SELECT id, email, password FROM users WHERE email = ?")
            .get(email);

        if (!user) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        res.json({
            message: "Login successful.",
            token,
            userId: user.id
        });

    } catch (error) {
        console.error("LOGIN ERROR:", error);

        res.status(500).json({
            error: "Could not log in."
        });
    }
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            error: "Authentication required."
        });
    }

    jwt.verify(
        token,
        process.env.JWT_SECRET,
        (error, user) => {
            if (error) {
                return res.status(403).json({
                    error: "Invalid or expired token."
                });
            }

            req.user = user;
            next();
        }
    );
}

app.get("/verify-token", authenticateToken, (req, res) => {
    res.json({
        valid: true,
        userId: req.user.userId
    });
});

app.get("/conversations", authenticateToken, (req, res) => {
    try {
        const conversations = db
            .prepare(`
                SELECT conversation_id, COALESCE(title, 'Previous conversation') AS title, created_at, updated_at
                FROM conversations
                WHERE user_id = ?
                ORDER BY updated_at DESC, id DESC
            `)
            .all(req.user.userId);

        res.json({ conversations });

    } catch (error) {
        console.error("CONVERSATIONS ERROR:", error);

        res.status(500).json({
            error: "Could not load conversations."
        });
    }
});

app.get("/conversations/:conversationId/messages", authenticateToken, (req, res) => {
    try {
        const conversationId = req.params.conversationId;

        const conversation = db
            .prepare(`
                SELECT id
                FROM conversations
                WHERE conversation_id = ?
                AND user_id = ?
            `)
            .get(conversationId, req.user.userId);

        if (!conversation) {
            return res.status(404).json({
                error: "Conversation not found."
            });
        }

        const messages = db
            .prepare(`
                SELECT role, content, created_at
                FROM messages
                WHERE conversation_id = ?
                ORDER BY id ASC
            `)
            .all(conversationId);

        res.json({ messages });

    } catch (error) {
        console.error("MESSAGES ERROR:", error);

        res.status(500).json({
            error: "Could not load conversation messages."
        });
    }
});

app.post("/chat", authenticateToken, aiLimiter, async (req, res) => {
    try {
        const message = req.body.message;

        if (typeof message !== "string" || !message.trim()) {
            return res.status(400).json({
                error: "Message is required."
            });
        }

        if (message.length > 10000) {
            return res.status(413).json({
                error: "Message is too long."
            });
        }

        console.log("sending:", message);

        const conversationId = req.body.conversationId;

if (!conversationId) {
    return res.status(400).json({
        error: "Conversation ID is required."
    });
}

const existingConversation = db
    .prepare(`
        SELECT id
        FROM conversations
        WHERE conversation_id = ?
    `)
    .get(conversationId);

if (existingConversation) {

    const userConversation = db
        .prepare(`
            SELECT id
            FROM conversations
            WHERE conversation_id = ?
            AND user_id = ?
        `)
        .get(conversationId, req.user.userId);

    if (!userConversation) {
        return res.status(403).json({
            error: "You do not have access to this conversation."
        });
    }

} else {

    const conversationTitle = message
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 60);

    db.prepare(`
        INSERT INTO conversations
        (user_id, conversation_id, title)
        VALUES (?, ?, ?)
    `).run(
        req.user.userId,
        conversationId,
        conversationTitle
    );
}

if (!conversations.has(conversationId)) {
    const savedMessages = db
        .prepare(
            "SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY id ASC"
        )
        .all(conversationId);

    conversations.set(conversationId, savedMessages);
}


const history = conversations.get(conversationId);

const memories = db
    .prepare("SELECT memory FROM memories WHERE user_id = ? ORDER BY created_at DESC")
    .all(req.user.userId);

    const memoryContext = memories.length
    ? memories.map(item => "- " + item.memory).join("\n")
    : "No saved memories.";

        const response = await
        openai.responses.create({
            model: "gpt-5.6-luna",
            input: [
    {
        role: "system",
        content: "You are Ubuntu Voice. You understand and speak Shona and English perfectly. ALWAYS respond in Shona first. IMPORTANT: In Shona, 'Unonzani?' is a natural question about a person's identity or name. Depending on context, it can mean 'Who are you?' or 'What is your name?'. If someone explicitly asks for a full name, including surname, provide the full name. Do not assume that 'Unonzani?' is asking for the surname unless the user makes that explicit. If you cannot understand, ask in Shona: 'Handina kunyatsonzwisisa, ndapota taura zvakare.' Be warm, intelligent, and helpful."
    },
    {
    role: "system",
    content: "Known information about this user:\n" + memoryContext
},
    ...history,
    {
        role: "user",
        content: message
    }
]
        });
        const reply = response.output_text;

        db.prepare(
    "INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)"
).run(conversationId, "user", message);

db.prepare(
    "INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)"
).run(conversationId, "assistant", reply);

        const lowerMessage = message.toLowerCase().trim();

if (
    lowerMessage.includes("my name is ") ||
    lowerMessage.includes("my favourite ") ||
    lowerMessage.includes("my favorite ") ||
    lowerMessage.includes("i like ") ||
    lowerMessage.includes("i love ") ||
    lowerMessage.includes("ndinonzi ") ||
    lowerMessage.includes("zita rangu ndi") ||
    lowerMessage.includes("ndinoda ")
) {
    db.prepare(
        "INSERT INTO memories (user_id, memory) VALUES (?, ?)"
    ).run(req.user.userId, message);
}

        history.push(
    {
        role: "user",
        content: message
    },
    {
        role: "assistant",
        content: reply
    }
);

        console.log("Reply received");

        res.json({ reply });

    } catch (error) {
        console.error("FULL ERROR:", error);

        res.status(500).json({
            reply: "Sorry, Ubuntu Voice could not connect to the AI."
        });
        }
    });
    
    app.post("/feedback", authenticateToken, (req, res) => {
    const { conversationId, rating } = req.body;

    if (!conversationId || !rating) {
        return res.status(400).json({
            error: "Conversation ID and rating are required."
        });
    }

    const conversation = db
        .prepare(`
            SELECT id
            FROM conversations
            WHERE conversation_id = ?
            AND user_id = ?
        `)
        .get(conversationId, req.user.userId);

    if (!conversation) {
        return res.status(403).json({
            error: "You do not have access to this conversation."
        });
    }

    db.prepare(`
        INSERT INTO feedback (user_id, conversation_id, rating)
        VALUES (?, ?, ?)
    `).run(req.user.userId, conversationId, rating);

    res.json({ success: true });
});

    app.post("/speak", authenticateToken, aiLimiter, async (req, res) => {
    try {
        const { text } = req.body;

if (typeof text !== "string" || !text.trim()) {
    return res.status(400).json({
        error: "Speech text is required."
    });
}

if (text.length > 5000) {
    return res.status(413).json({
        error: "Speech text is too long."
    });
}

console.log("Generating speech...");
        const mp3 = await openai.audio.speech.create({
            model: "gpt-4o-mini-tts",
            voice: "coral",
            instructions:
                "Speak naturally and fluently. When the text is English, use natural fluent English pronunciation. When the text is Shona, speak with natural Zimbabwean Shona pronunciation and rhythm. Use authentic Shona vowel and consonant sounds, natural Shona stress and intonation, and connected speech. Do not pronounce Shona words as though they were English words. The Shona should sound natural and fluent, not like an English speaker reading Shona.",
            input: text
        });

        const audioBuffer = Buffer.from(
            await mp3.arrayBuffer()
        );

        res.setHeader("Content-Type", "audio/mpeg");
        res.send(audioBuffer);

        console.log("Audio ready!");

    } catch (error) {
        console.error("TTS ERROR:", error);

        res.status(500).json({
            error: "Could not generate speech"
        });
    }
});
    app.post("/transcribe",
      authenticateToken, aiLimiter, upload.single("file"), async (req, res) =>
        {
            try {
                if (!req.file) {
    return res.status(400).json({
        error: "Audio file is required."
    });
}

console.log("Transcribing audio...");

const transcription = await openai.audio.transcriptions.create({
  file: new File(
    [req.file.buffer],
    "recording.webm",
    { type: "audio/webm;codecs=opus" }
  ),
  model: "gpt-transcribe",
  prompt: "The speaker is speaking Shona, a language of Zimbabwe. Transcribe the Shona speech accurately. Common Shona words include: mhoro, makadii, unonzani, ndiani, uri ani, chii, sei, sei wakadaro."
});

                console.log("Transcription:",
                    transcription.text);

                res.json({ text: transcription.text });

            } catch (error) {
                console.error(" TRANSCRIPTION ERROR:",
                    error);

                    res.status(500).json({
                        error: "Ndine urombo, handina kukwanisa kunyora zvawataura.",
                        details: error.message
                     });
                }
            });
    app.listen(process.env.PORT || 3000, () => {
    console.log(`Ubuntu Voice backend running on port ${process.env.PORT || 3000}`);
    console.log("Model: GPT-5.6 Luna | OpenAI Responses API");
});
