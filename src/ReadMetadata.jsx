import { Link, useNavigate } from "react-router-dom";
import { useEffect, useState, useRef } from "react";
import MetadataViewer from "./MetadataViewer";

export default function ReadMetadata() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [result, setResult] = useState(null);

  const [jsonFileRaw, setJsonFileRaw] = useState(null);
  const [jsonFileName, setJsonFileName] = useState("");
  const [jsonFilesSize, setJsonFilesSize] = useState(null);

  const imageInputRef = useRef(null);
  const jsonInputRef = useRef(null);

  useEffect(() => {
    if (!file) {
      setPreviewUrl("");
      return;
    }
    const url = URL.createObjectURL(file);
    setPreviewUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [file]);

  // Select and validate JPEG/PNG
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

    if (jsonInputRef.current) {
      jsonInputRef.current.value = "";
    }
    setJsonFileRaw(null);
    setJsonFileName("");
    setJsonFilesSize(null);

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


  const downloadDisplayedJSON = () => {
    if (!result) return;

    // use the same object MetadataViewer receives
    const displayed = result;

    // include some minimal local context (file name/size)
    const context = {
      fileName: file?.name ?? null,
      fileSize: file?.size ?? null,
      // you currently avoid embedding previewUrl, so just omit it
    };

    const finalObj = {
      ...Object.fromEntries(
        Object.entries(context).filter(([, v]) => v != null)
      ),
      data: displayed,
    };

    const text = JSON.stringify(finalObj, null, 2);
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const baseName = file?.name ? file.name.replace(/\.[^.]+$/, "") : "metadata";
    a.href = url;
    a.download = `${baseName}.displayed.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const onJSONPick = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setError("");
    setStatus("");

    if (imageInputRef.current) {
      imageInputRef.current.value = "";
    }

    setFile(null);
    setPreviewUrl("");

    // basic JSON file check
    if (!/\.json$/i.test(f.name) && !/json/.test(f.type)) {
      setError("Please select a JSON file.");
      setJsonFileRaw(null);
      setJsonFileName("");
      setJsonFilesSize(null);
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(reader.result);
        setJsonFileRaw(parsed);
        setJsonFileName(f.name || "");
        setJsonFilesSize(typeof f.size == "number" ? f.size : null);

        setStatus("JSON loaded");
      } catch (err) {
        setError("Invalid JSON file.");
        setJsonFileRaw(null);
        setJsonFileName("");
        setJsonFileSize(null);
      }
    };
    reader.readAsText(f);
  };

  // Use the loaded JSON to (re)build what MetadataViewer should show
  const displayJson = () => {
    if (!jsonFileRaw) {
      setError("No JSON file loaded.");
      return;
    }

    setError("");
    setStatus("");

    const parsed = jsonFileRaw;

    // If this is a round-tripped file from Download Displayed JSON, use the inner `data`
    const viewerData =
      parsed && typeof parsed === "object" && parsed.data !== undefined
        ? parsed.data
        : parsed;

    // Heuristic detection of format based on keys; same idea as before
    const probe = viewerData;
    const keys = Array.isArray(probe) ? [] : Object.keys(probe ?? {});
    const keyStr = keys.join(" ").toLowerCase();

    let detected = null;
    if (/png|ihdr|chunks|plte|t(e|)xt|ztxt/.test(keyStr)) detected = "png";
    if (/exif|app|jfif|jpeg|jpg|markers|soi|dqt|dht/.test(keyStr)) {
      detected = detected || "jpeg";
    }

    const toDisplay =
      viewerData && typeof viewerData === "object"
        ? {
            ...viewerData,
            _detected_format:
              viewerData._detected_format != null
                ? viewerData._detected_format
                : detected,
          }
        : viewerData;

    setResult(toDisplay);
    setStatus("Displaying JSON");
  };

  return (
    <div
      className="container"
      style={{ 
        display: "flex", 
        flexDirection: "column", 
        gap: 12, 
        alignItems: "center", 
        textAlign: "center" 
      }}
    >
      <h2>Upload Image</h2>
      <p>Pick a JPEG or PNG and analyze it.</p>

      <input
        ref = {imageInputRef}
        type="file"
        accept="image/jpeg,image/png"
        onChange={onPick}
      />

      {error && (
        <div role="alert" style={{ color: "crimson", marginTop: 8 }}>
          {error}
        </div>
        )}

      {previewUrl && (
        <div style={{ marginTop: 12 }}>
          <img 
          src={previewUrl} 
          alt="Preview" 
          style={{ maxWidth: 320, borderRadius: 8 }} />
        </div>
      )}

      <div 
        style={{ 
          marginTop: 12, 
          width: "100%", 
          display: "flex", 
          justifyContent: "center" 
        }}
      >
        <button onClick={analyze} disabled={!file}>
          Analyze
          </button>
        {status && (
          <span role="status" style={{ marginLeft: 10 }}>
            {status}
          </span>
          )}
      </div>

      <div 
        style={{ 
          marginTop: 12, 
          width: "100%", 
          display: "flex", 
          justifyContent: "center", 
          gap: 8,
        }}
      >
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          Load JSON:
          <input 
          ref = {jsonInputRef}
          type="file" 
          accept=".json,application/json" 
          onChange={onJSONPick} />
        </label>
        <button onClick = {displayJson} disabled = {!jsonFileRaw}>
          Display JSON
        </button>
      </div>


      {result && (
        <div 
          style={{ 
              width: "100%", 
              display: "flex", 
              flexDirection: "column", 
              alignItems: "center", 
              gap: 8, 
          }}
        >
          <div style={{ marginTop: 8 }}>
            <button onClick={downloadDisplayedJSON}>
              Download Displayed JSON
            </button>
          </div>
          <MetadataViewer data={result} />
        </div>
      )}

      <div 
        style={{ 
          marginTop: 16, 
          width: "100%", 
          display: "flex", 
          justifyContent: "center" }}
      >
        <button onClick={() => navigate("/")} 
          style={{ padding: "8px 16px" }}>
            Back to Home
        </button>
      </div>
    </div>
  );
}