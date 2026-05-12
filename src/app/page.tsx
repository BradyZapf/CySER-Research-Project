"use client";

import { useState } from "react";
import { analyzePrompt, DetectionResult } from "@/lib/detector";

export default function Home() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<DetectionResult | null>(null);

  const handleAnalyze = () => {
    const res = analyzePrompt(input);
    setResult(res);
  };

  function getColor(risk: string) {
  if (risk === "Safe") return "green";
  if (risk === "Suspicious") return "orange";
  return "red";
}

function getTypeColor(type: string) {
  if (type === "Goal Hijacking") return "#c0392b";
  if (type === "Prompt Leaking") return "#2980b9";
  if (type === "Role Manipulation") return "#e67e22";
  if (type === "Delimiter Injection") return "#8e44ad";
  if (type === "Fictional Framing") return "#16a085";
  if (type === "Privilege Escalation") return "#922b21";
  if (type === "Obfuscation") return "#616a6b";
  if (type === "Indirect Injection") return "#2c3e50";
  if (type === "Tool Abuse") return "#d35400";
  if (type === "RAG Poisoning") return "#117a65";
  if (type === "Data Exfiltration") return "#6c3483";
  if (type === "Harmful Content") return "#7b241c";
  if (type === "Social Engineering") return "#784212";
  return "black";
}

function escapeRegex(str: string) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function highlightText(text: string, matches: { matchedText: string }[]) {
  let result = text;

  matches.forEach((match) => {
    if (!match.matchedText || match.matchedText.startsWith("[")) {
      return;
    }

    const regex = new RegExp(`(${escapeRegex(match.matchedText)})`, "gi");

    result = result.replace(
      regex,
      `<span style="background-color: yellow; font-weight: bold;">$1</span>`
    );
  });

  return result;
}

  return (
  <main style={{ padding: "2rem", fontFamily: "Arial", maxWidth: "800px", margin: "auto" }}>
    <h1 style={{ fontSize: "2rem", fontWeight: "bold" }}>
      Prompt Injection Detector
    </h1>

    <textarea
      rows={6}
      style={{
        width: "100%",
        marginTop: "1rem",
        padding: "0.5rem",
        borderRadius: "8px",
        border: "1px solid #ccc"
      }}
      placeholder="Enter a prompt..."
      value={input}
      onChange={(e) => setInput(e.target.value)}
    />

    <button
      onClick={handleAnalyze}
      style={{
        marginTop: "1rem",
        padding: "0.5rem 1rem",
        borderRadius: "8px",
        backgroundColor: "#0070f3",
        color: "white",
        border: "none",
        cursor: "pointer"
      }}
    >
      Analyze
    </button>

    {result && (
      <div
        style={{
          marginTop: "2rem",
          padding: "1rem",
          borderRadius: "10px",
          border: "1px solid #ddd",
          backgroundColor: "#f9f9f9",
          color: "#111",
          boxShadow: "0 2px 8px rgba(0,0,0,0.1)"
        }}
      >

        <h3>- Analyzed Input</h3>
        <p
          dangerouslySetInnerHTML={{
            __html: highlightText(input, result.matches),
          }}
        />

        <h2 style={{ color: "#000" }}>- Analysis Result</h2>

        <p>
          <strong>Risk Level:</strong>{" "}
          <span style={{ color: getColor(result.riskLevel), fontWeight: "bold" }}>
            {result.riskLevel}
          </span>
        </p>

        <p><strong>Score:</strong> {result.score}</p>

        <p>
          <strong>Attack Type:</strong>{" "}
          {result.attackTypes && result.attackTypes.length > 0
            ? result.attackTypes.join(", ")
            : "None"}
        </p>

        <p style={{ color: "#333" }}>
        <strong>Explanation:</strong> {result.explanation}
        </p>

        <h3>- Analysis Steps</h3>
        <ul style={{ color: "#222", lineHeight: "1.6" }}>
          {result.steps.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ul>

        <hr style={{ margin: "1rem 0" }} />

        <h3>- Detected Attacks</h3>

        {result.matches.length === 0 ? (
          <p>No suspicious patterns detected.</p>
        ) : (
          Object.entries(
            result.matches.reduce((acc, match) => {
              if (!acc[match.type]) acc[match.type] = [];
              acc[match.type].push(match);
              return acc;
            }, {} as Record<string, typeof result.matches>)
            ).map(([type, matches]) => (
            <div key={type} style={{ marginBottom: "1rem" }}>
              <h4 style={{ color: getTypeColor(type) }}>{type}</h4>

              <ul>
                {matches.map((m, i) => (
                  <li key={i}>
                    <strong>{m.phrase}</strong>
                    <br />
                    <span style={{ color: "#555" }}>{m.reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))
        )}
      </div>
    )}
  </main>
);
}