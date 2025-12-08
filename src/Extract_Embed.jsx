import { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function ExtractEmbed() {
    const navigate = useNavigate();
    const [operation, setOperation] = useState("extract");
    const [file, setFile] = useState(null);
    const [message, setMessage] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [stegoB64, setStegoB64] = useState(null);
    const [parsedData, setParsedData] = useState(null);

    // reset password and message fields in the UI
    const resetFields = () => {
        setPassword("");
        setMessage("");
    };

    const parseJsonLines = (text) => {
        // try top-level JSON first
        try {
            return JSON.parse(text);
        } catch (e) {
            // split into lines and parse each JSON object
            const lines = text.trim().split(/\r?\n/).map(l => l.trim()).filter(Boolean);
            const objs = [];
            for (const line of lines) {
                try {
                    objs.push(JSON.parse(line));
                } catch (err) {
                    // ignore unparsable lines
                }
            }
            if (objs.length === 0) return null;
            // merge objects (later keys overwrite earlier)
            return Object.assign({}, ...objs);
        }
    };

    const onSubmit = async (e) => {
        e.preventDefault();
        if (!file) {
            alert("Please select an image file.");
            return;
        }
        setLoading(true);
        setResult(null);
        setStegoB64(null);
        setParsedData(null);

        const fd = new FormData();
        fd.append("file", file);
        fd.append("mode", operation);
        fd.append("password", password);
        if (operation === "embed") fd.append("message", message);

        try {
            const res = await fetch("http://localhost:8000/api/secret", {
                method: "POST",
                body: fd,
            });

            const text = await res.text();
            const data = parseJsonLines(text);

            if (data?.stego_image_b64) setStegoB64(data.stego_image_b64);
            setParsedData(data);

            if (!res.ok) {
                const errMsg = data?.detail ?? data?.error ?? text ?? `HTTP ${res.status}`;
                setResult("Error: " + errMsg);
            } else {
                // Clear fields ONLY on success
                resetFields();

                if (operation === "embed") {
                    const outPath = data.output_path ?? null;
                    const bytes = data.bytes_embedded ?? null;
                    setResult(
                        `Embedded successfully.` +
                        (outPath ? ` Output: ${outPath}` : "") +
                        (bytes !== null ? ` (${bytes} bytes embedded)` : "")
                    );
                } else {
                    const msg = data.message ?? data.extracted ?? null;
                    setResult((msg ? msg : (data.result_message ?? "Extracted successfully.")));
                }
            }
        } catch (err) {
            setResult("Request failed: " + String(err));
        } finally {
            setLoading(false);
        }
    };

    // helper to get downloadable href and extension if we have base64
    const downloadHref = () => {
        const b64 = stegoB64 ?? parsedData?.stego_image_b64;
        if (!b64) return null;
        const mime = parsedData?.mime_type ?? "image/jpeg";
        return { href: `data:${mime};base64,${b64}`, mime };
    };

    return (
        <div
            className="container"
            style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}
        >
            <h2>Embed / Extract</h2>

            <form onSubmit={onSubmit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                {/* First row: Select File + Operation */}
                <div style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
                    <label style={{ flex: 1 }}>
                        Select File:
                        <input
                            type="file"
                            accept=".jpg,.jpeg,.png"
                            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                        />
                        <small style={{ display: "block", marginTop: 6 }}>Choose a .jpg/.jpeg/.png image </small>
                    </label>

                    <label style={{ width: 220 }}>
                        Operation:
                        <select value={operation} onChange={(e) => setOperation(e.target.value)}>
                            <option value="extract">Extract</option>
                            <option value="embed">Embed</option>
                        </select>
                        <small style={{ display: "block", marginTop: 6 }}>Select Embed or Extract</small>
                    </label>
                </div>

                {/* Second row: Embed => Message + Password | Extract => Password only */}
                {operation === "embed" ? (
                    <div style={{ display: "flex", gap: 16 }}>
                        <label style={{ flex: 1 }}>
                            Secret Message:
                            <textarea
                                value={message}
                                onChange={(e) => setMessage(e.target.value)}
                                rows={4}
                                style={{ width: "100%" }}
                            />
                            <small style={{ display: "block", marginTop: 6 }}>Secret message to embed inside the image</small>
                        </label>

                        <label style={{ width: 220 }}>
                            Password:
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                style={{ width: "100%" }}
                            />
                            <small style={{ display: "block", marginTop: 6 }}>Password used to protect the secret</small>
                        </label>
                    </div>
                ) : (
                    <div style={{ display: "flex", gap: 16 }}>
                        <label style={{ flex: 1 }}>
                            Password:
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                style={{ width: "100%" }}
                            />
                            <small style={{ display: "block", marginTop: 6 }}>Enter password to decrypt the secret</small>
                        </label>
                    </div>
                )}

                {/* Third row: action button centered */}
                <div style={{ display: "flex", justifyContent: "center" }}>
                    <button type="submit" disabled={loading}>
                        {loading ? "Processing..." : operation === "embed" ? "Embed" : "Extract"}
                    </button>
                </div>
            </form>

            {/* Result / extracted message */}
            {result !== null && (
                (operation === "embed" ||
                 (typeof result === "string" &&
                   (result.toLowerCase().startsWith("error") ||
                    result.toLowerCase().startsWith("request failed")))) && (
                    <div className="result" style={{ marginTop: 12 }}>
                        <h3>Result</h3>
                        <pre>{result}</pre>
                    </div>
            ))}

            {/* Table view for structured output */}
            {parsedData && operation === "embed" && (
                <div style={{ marginTop: 12 }}>
                    <h3>Embed Output</h3>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead>
                            <tr>
                                <th style={{ textAlign: "left", borderBottom: "1px solid #ccc", padding: "6px" }}>Field</th>
                                <th style={{ textAlign: "left", borderBottom: "1px solid #ccc", padding: "6px" }}>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style={{ padding: "6px", borderBottom: "1px solid #eee" }}>Input File</td>
                                <td style={{ padding: "6px", borderBottom: "1px solid #eee" }}>{parsedData.input_path ?? parsedData.input ?? "—"}</td>
                            </tr>
                            <tr>
                                <td style={{ padding: "6px", borderBottom: "1px solid #eee" }}>Output File</td>
                                <td style={{ padding: "6px", borderBottom: "1px solid #eee" }}>
                                    {(() => {
                                        const dl = downloadHref();
                                        if (dl) {
                                            const ext = (dl.mime && dl.mime.includes("png")) ? "png" : "jpg";
                                            return <a href={dl.href} download={`stego.${ext}`}>Download stego.{ext}</a>;
                                        }
                                        return parsedData.output_path ?? parsedData.out_path ?? "—";
                                    })()}
                                </td>
                            </tr>
                            <tr>
                                <td style={{ padding: "6px" }}>Bytes Embedded</td>
                                <td style={{ padding: "6px" }}>{parsedData.bytes_embedded ?? parsedData.bytes ?? "0"}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            )}

            {parsedData && operation === "extract" && (
                <div style={{ marginTop: 12 }}>
                    <h3>Extracted Output</h3>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead>
                            <tr>
                                <th style={{ textAlign: "left", borderBottom: "1px solid #ccc", padding: "6px" }}>Recovered Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style={{ padding: "12px 6px 6px 6px", borderTop: "2px solid #000", whiteSpace: "pre-wrap" }}>
                                    {parsedData.message ?? parsedData.extracted ?? parsedData.result_message ?? "—"}
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            )}

            {/* If embed returned a base64 stego image, show a download link (redundant with table) */}
            {stegoB64 && (
                <div style={{ marginTop: 8, textAlign: "center" }}>
                    <a
                        href={`data:image/jpeg;base64,${stegoB64}`}
                        download="stego.jpg"
                    >
                        Download stego image
                    </a>
                </div>
            )}

            <div style={{ marginTop: "auto", padding: 16, textAlign: "center" }}>
                <button onClick={() => navigate("/")}>Back to Home</button>
            </div>
        </div>
    );
}