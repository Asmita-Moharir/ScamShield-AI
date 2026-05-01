import { useState, useEffect } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

/* ---------------------------------------
   API BASE URL FROM .env
--------------------------------------- */
const API = import.meta.env.VITE_API_URL;

function App() {
  const [mode, setMode] = useState("text");

  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [jobText, setJobText] = useState("");
  const [imageFile, setImageFile] = useState(null);

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const [history, setHistory] = useState([]);

  /* ---------------------------------------
     LOAD HISTORY
  --------------------------------------- */
  useEffect(() => {
    const saved = localStorage.getItem("scanHistory");

    if (saved) {
      setHistory(JSON.parse(saved));
    }
  }, []);

  /* ---------------------------------------
     SAVE HISTORY
  --------------------------------------- */
  const saveHistory = (scanType, score, level) => {
    const newItem = {
      type: scanType,
      score,
      level,
      time: new Date().toLocaleString(),
    };

    const updated = [newItem, ...history].slice(0, 10);

    setHistory(updated);
    localStorage.setItem("scanHistory", JSON.stringify(updated));
  };

  /* ---------------------------------------
     API CALLS
  --------------------------------------- */

  const scanText = async () => {
    const res = await axios.post(`${API}/analyze`, {
      text,
    });

    setResult(res.data);
    saveHistory("Text", res.data.score, res.data.risk_level);
  };

  const scanURL = async () => {
    const res = await axios.post(`${API}/scan-url`, {
      url,
    });

    setResult(res.data);
    saveHistory("URL", res.data.score, res.data.risk_level);
  };

  const scanJob = async () => {
    const res = await axios.post(`${API}/scan-job`, {
      text: jobText,
    });

    setResult(res.data);
    saveHistory("Job", res.data.score, res.data.risk_level);
  };

  const scanImage = async () => {
    const formData = new FormData();
    formData.append("file", imageFile);

    const res = await axios.post(`${API}/scan-image`, formData);

    setResult(res.data);
    saveHistory("OCR", res.data.score, res.data.risk_level);
  };

  const handleAnalyze = async () => {
    setLoading(true);
    setResult(null);

    try {
      if (mode === "text") await scanText();
      if (mode === "url") await scanURL();
      if (mode === "job") await scanJob();
      if (mode === "image") await scanImage();
    } catch (error) {
      console.log(error);
      alert("Backend error");
    }

    setLoading(false);
  };

  /* ---------------------------------------
     CHART DATA
  --------------------------------------- */

  const pieData = result
    ? [
        { name: "Risk", value: result.score },
        { name: "Safe", value: 100 - result.score },
      ]
    : [];

  const barData = history.map((item, index) => ({
    name: item.type + " " + (index + 1),
    score: item.score,
  }));

  /* ---------------------------------------
     CLEAR HISTORY
  --------------------------------------- */

  const clearHistory = () => {
    localStorage.removeItem("scanHistory");
    setHistory([]);
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-gradient-to-br from-black via-gray-950 to-gray-900 text-white">
      {/* Glow */}
      <div className="absolute top-20 left-10 w-72 h-72 bg-green-500/10 blur-3xl rounded-full"></div>
      <div className="absolute bottom-20 right-10 w-96 h-96 bg-emerald-400/10 blur-3xl rounded-full"></div>

      <div className="relative z-10">
        {/* Navbar */}
        <nav className="flex justify-between items-center px-8 py-5 border-b border-white/10">
          <h1 className="text-3xl font-bold text-green-400">
            ScamShield AI
          </h1>

          <span className="text-gray-400 text-sm">
            Detect Before You Click
          </span>
        </nav>

        {/* Hero */}
        <div className="text-center px-6 py-14 max-w-5xl mx-auto">
          <h2 className="text-6xl font-bold leading-tight">
            Protect Yourself From
            <span className="text-green-400"> Scams </span>
            Instantly
          </h2>

          <p className="text-gray-400 mt-5 text-lg">
            Scan text, URLs, fake jobs and screenshots.
          </p>
        </div>

        {/* Scanner */}
        <div className="max-w-4xl mx-auto px-6">
          <div className="bg-white/5 border border-white/10 rounded-3xl p-6">

            {/* Modes */}
            <div className="grid md:grid-cols-4 gap-3 mb-5">
              {[
                ["text", "Text"],
                ["url", "URL"],
                ["job", "Job Scam"],
                ["image", "OCR"],
              ].map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => {
                    setMode(key);
                    setResult(null);
                  }}
                  className={`px-5 py-3 rounded-xl font-semibold ${
                    mode === key
                      ? "bg-green-500"
                      : "bg-gray-800 text-gray-300"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Inputs */}
            {mode === "text" && (
              <textarea
                rows="8"
                className="w-full bg-black/30 border border-gray-700 rounded-2xl p-4"
                placeholder="Paste suspicious text..."
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
            )}

            {mode === "url" && (
              <input
                type="text"
                className="w-full bg-black/30 border border-gray-700 rounded-2xl p-4"
                placeholder="Enter suspicious URL..."
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            )}

            {mode === "job" && (
              <textarea
                rows="8"
                className="w-full bg-black/30 border border-gray-700 rounded-2xl p-4"
                placeholder="Paste suspicious job offer..."
                value={jobText}
                onChange={(e) => setJobText(e.target.value)}
              />
            )}

            {mode === "image" && (
              <input
                type="file"
                accept="image/*"
                className="w-full bg-black/30 border border-gray-700 rounded-2xl p-4"
                onChange={(e) => setImageFile(e.target.files[0])}
              />
            )}

            {/* Button */}
            <button
              onClick={handleAnalyze}
              className="w-full mt-5 py-3 rounded-2xl bg-green-500 hover:bg-green-600 font-bold text-lg"
            >
              {loading ? "Scanning..." : "Analyze Now"}
            </button>
          </div>
        </div>

        {/* Result */}
        {result && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="max-w-4xl mx-auto px-6 mt-10"
          >
            <div className="bg-white/5 border border-white/10 rounded-3xl p-6">

              <h3 className="text-3xl font-bold mb-6">
                Scan Result
              </h3>

              <div className="grid md:grid-cols-2 gap-4 mb-6">
                <div className="bg-black/30 rounded-2xl p-5">
                  <p className="text-gray-400">Risk Score</p>
                  <p className="text-5xl font-bold">
                    {result.score}%
                  </p>
                </div>

                <div className="bg-black/30 rounded-2xl p-5">
                  <p className="text-gray-400">Risk Level</p>
                  <p className="text-4xl font-bold text-red-400">
                    {result.risk_level}
                  </p>
                </div>
              </div>

              {/* Reasons */}
              <div className="mt-6 space-y-3">
                {result.reasons.map((item, index) => (
                  <div
                    key={index}
                    className="bg-black/30 border border-white/10 p-4 rounded-xl"
                  >
                    {item}
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* Dashboard */}
        {history.length > 0 && (
          <div className="max-w-5xl mx-auto px-6 mt-12 pb-14">

            <div className="flex justify-between items-center mb-5">
              <h3 className="text-3xl font-bold text-green-400">
                Scan Dashboard
              </h3>

              <button
                onClick={clearHistory}
                className="px-4 py-2 bg-red-500 rounded-xl"
              >
                Clear History
              </button>
            </div>

            {/* Bar Chart */}
            <div className="bg-white/5 border border-white/10 rounded-3xl p-6 mb-6 h-80">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" stroke="#aaa" />
                  <YAxis stroke="#aaa" />
                  <Tooltip />
                  <Bar dataKey="score" fill="#22c55e" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* History Cards */}
            <div className="grid md:grid-cols-2 gap-4">
              {history.map((item, index) => (
                <div
                  key={index}
                  className="bg-white/5 border border-white/10 rounded-2xl p-5"
                >
                  <p className="text-green-400 font-bold">
                    {item.type} Scan
                  </p>

                  <p className="mt-2">Risk Score: {item.score}%</p>
                  <p>Level: {item.level}</p>
                  <p className="text-gray-400 text-sm mt-2">
                    {item.time}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

export default App;