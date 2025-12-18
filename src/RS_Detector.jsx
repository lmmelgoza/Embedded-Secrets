import { useState } from "react";

export default function RS_Detector() {
  const [file, setFile] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const handleFileChange = (event) => {
    const selected = event.target.files?.[0];
    setFile(selected || null);
    setError("");
    setResult(null);
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError("Please upload a JPEG or PNG image first.");
      return;
    }

    setIsAnalyzing(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      // If you have a dev proxy set up, you can just use "/rs-analyze"
      const response = await fetch("http://localhost:8000/rs-analyze", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        let detail = "RS analysis failed.";
        try {
          const errJson = await response.json();
          if (errJson?.detail) detail = errJson.detail;
        } catch (_) {
          // ignore JSON parse error
        }
        throw new Error(detail);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Something went wrong while analyzing the image.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const verdictColor =
    result?.rs?.verdict === "suspicious" ? "#b91c1c" : "#15803d";

  return (
    <div className="container" style={{ display: "flex", flexDirection: "column", gap: "1rem", maxWidth: 500 }}>
      {/* Top text */}
      <h1 style={{ textAlign: "center" }}>
        Scan a JPEG/PNG for embedding
      </h1>

      {/* Upload file button */}
      <label
        className="primary-btn"
        style={{ textAlign: "center", cursor: "pointer" }}
      >
        Upload Image
        <input
          type="file"
          accept="image/jpeg,image/png"
          onChange={handleFileChange}
          style={{ display: "none" }}
        />
      </label>
      {file && (
        <p style={{ fontSize: "0.9rem", textAlign: "center" }}>
          Selected file: <strong>{file.name}</strong>
        </p>
      )}

      {/* Analyze button */}
      <button
        className="primary-btn"
        onClick={handleAnalyze}
        disabled={!file || isAnalyzing}
      >
        {isAnalyzing ? "Analyzing..." : "Run RS Analysis"}
      </button>

      {/* Error display */}
      {error && (
        <p style={{ color: "#b91c1c", textAlign: "center" }}>
          {error}
        </p>
      )}

      {/* Result display */}
      {result && result.rs && (
        <div
          style={{
            marginTop: "1rem",
            padding: "1rem",
            borderRadius: "0.5rem",
            border: "1px solid #e5e7eb",
          }}
        >
          <h2 style={{ marginBottom: "0.5rem" }}>
            Result for {result.filename}
          </h2>
          <p>Format: {result.format}</p>
          <p>
            Suspicion score:{" "}
            {typeof result.rs.score === "number"
              ? result.rs.score.toFixed(6)
              : result.rs.score}
          </p>
          <p>
            Verdict:{" "}
            <span style={{ fontWeight: 600, color: verdictColor }}>
              {result.rs.verdict === "suspicious"
                ? "Suspicious"
                : "Likely clean"}
            </span>
          </p>
          <details style={{ marginTop: "0.75rem" }}>
            <summary>View RS details</summary>
            <pre
              style={{
                marginTop: "0.5rem",
                fontSize: "0.8rem",
                background: "#000000ff",
                padding: "0.75rem",
                borderRadius: "0.5rem",
                overflowX: "auto",
              }}
            >
            {JSON.stringify(result.rs, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}
