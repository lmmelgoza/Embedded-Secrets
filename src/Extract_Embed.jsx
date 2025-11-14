import { useState } from "react";

export default function ExtractEmbed() {
    const [operation, setOperation] = useState("extract");
    const [file, setFile] = useState(null);
    const [message, setMessage] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);

    const onSubmit = async (e) => {
        e.preventDefault();
        if (!file) {
            alert("Please select a JPEG image file.");
            return;
        }
        setLoading(true);
        setResult(null);

        const fd = new FormData();
        fd.append("file", file);
        fd.append("operation", operation);
        fd.append("password", password);
        if (operation == "embed") fd.append("message", message);

        try {
            const res = await fetch("/api/secret", {
                method: "POST",
                body: fd,
            });
            const text = await res.text();
            setResult(text);
        } catch (err) {
            setResult("Request failed: " + String(err));
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className = "container">
            <h2>Embed / Extract</h2>
            <form onSubmit={onSubmit}>
                <label>
                    Select File:
                    <input
                        type = "file"
                        accept = ".jpg,.jpeg"
                        onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                        />
                </label>

                <label>
                    Operation:
                    <select value = {operation} onChange={(e) => setOperation(e.target.value)}>
                        <option value="extract">Extract</option>
                        <option value="extract">EEmbed</option>
                    </select>
                </label>

                {operation == "embed" && (
                    <label>
                        Message to embed:
                        <textarea
                            value={message}
                            onChange={(e) => setMessage(e.target)}
                            rows={4}
                        />
                    </label>
                )}

                <label>
                    Password:
                    <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                </label>

                <button type="submit" disabled={loading}>
                    {loading ? "Processing..." : operation == "embed" ? "Embed" : "Extract"}
                </button>
            </form>

            {result !== null && (
                <div className = "result">
                    <h3>Result</h3>
                    <pre>{result}</pre>
                </div>
            )}
        </div>
    )
}