const express = require("express");
const multer = require("multer");
const { exec } = require("child_process");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const app = express();
const upload = multer({ dest: "uploads/" });

app.use(cors());
app.use(express.json());

app.post("/upload", upload.single("apk"), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
    }

    const apkPath = path.join(__dirname, req.file.path);
    
    // Run Python script
    exec(`python3 apk_scanner.py ${apkPath}`, (error, stdout, stderr) => {
        // Delete the APK after scanning
        fs.unlinkSync(apkPath);

        if (error) {
            return res.status(500).json({ error: stderr || "Error executing script" });
        }

        try {
            const result = JSON.parse(stdout); // Parse the Python script output
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: "Invalid JSON output from Python script" });
        }
    });
});

app.listen(5000, () => console.log("Server running on port 5000"));
