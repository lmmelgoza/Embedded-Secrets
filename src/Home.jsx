import { useNavigate } from "react-router-dom";

export default function Home() {
  const navigate = useNavigate();
  return (
    <div className="container">
      <button className="primary-btn" onClick={() => navigate("/read_metadata")}>
        Upload & Analyze Image
      </button>
      <button className="primary-btn" onClick={() => navigate("/extract_embed")}>
        Embed/Extract Secret Message
      </button>
      <button className="primary-btn" onClick={() => navigate("/rs_detector")}>
        RS Steganalysis Detector
      </button>
    </div>
  );
}
