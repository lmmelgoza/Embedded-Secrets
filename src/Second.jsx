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
    const isPngMime = /image\/png/i.test(f.type);
    const isPngExt = /\.png$/i.test(f.name);

    const isJpeg = isJpegMime || isJpegExt;
    const isPng = isPngMime || isPngExt;

    if (!isJpeg && !isPng) {
      setError("Please select a JPEG or PNG image.");
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
      let safeName = file.name;
      if (!/\.jpe?g$/i.test(safeName) && !/\.png$/i.test(safeName)) {
        safeName = /image\/png/i.test(file.type) ? `${safeName}.png` : `${safeName}.jpg`;
      }
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
      <h2>Upload Image</h2>
      <p>Pick a JPEG or PNG analyze it with the Python backend.</p>

      <input type="file" accept="image/jpeg,image/jpeg,image/png" onChange={onPick} />

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