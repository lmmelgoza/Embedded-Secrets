import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import MetadataViewer from "./MetadataViewer";

export default function Second() {
  const [file, setFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!file) {
      setPreviewUrl("");
      return;
    }
    const url = URL.createObjectURL(file);
    setPreviewUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [file]);

  // Select and validate JPEG
  const onPick = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;

    setError("");
    setStatus("");

    const isJpegMime = /image\/jpeg/i.test(f.type);
    const isJpegExt = /\.jpe?g$/i.test(f.name);
    if (!isJpegMime && !isJpegExt) {
      setError("Please select a JPEG image.");
      setFile(null);
      return;
    }

    const MAX = 5 * 1024 *1024; //5MB
    if (f.size > MAX) {
      setError("File size exceeds 5MB.");
      setFile(null);
      return;
    }
    setFile(f);
  };

  const analyze = async () => {
    if (!file) return;
    try {
      setError("");
      setStatus("Analyzing...");

      const formData = new FormData();
      const safeName = /\.jpe?g/i.test(file.name) ? file.name : `${file.name}.jpg`;
      formData.append("file", file, safeName);

      const res = await fetch("http://localhost:8000/analyze", { method: "POST", body: formData });
      const json = await res.json();
      console.log("analyze response:", json);
      
      if (!res.ok || json.error) throw new Error(json.error || `HTTP ${res.status}`);
      setResult(json);
      setStatus("Analysis complete!");
    } catch (err) {
      setStatus("");
      setResult(null);
      setError(err?.message || "Analysis failed.");
    }
  };

  return (
    <div className="container">
      <h2>Second Page</h2>
      <p>Pick a JPEG and analyze it with the Python backend.</p>

      <input type="file" accept="image/jpeg,image/jpg" onChange={onPick} />

      {error && <div role="alert" style={{ color: "crimson", marginTop: 8 }}>{error}</div>}

      {previewUrl && (
        <div style={{ marginTop: 12 }}>
          <img src={previewUrl} alt="Preview" style={{ maxWidth: 320, borderRadius: 8 }} />
        </div>
      )}

      <div style={{ marginTop: 12 }}>
        <button onClick={analyze} disabled={!file}>Analyze</button>
        {status && <span role="status" style={{ marginLeft: 10 }}>{status}</span>}
      </div>

      {result && <MetadataViewer data={result} />}

      <div style={{ marginTop: 16 }}>
        <Link to="/" className="link-btn">Back to Home</Link>
      </div>
    </div>
  );
}