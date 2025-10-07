import { useNavigate } from "react-router-dom";

export default function Home() {
  const navigate = useNavigate();
  return (
    <div className="container">
      <button className="primary-btn" onClick={() => navigate("/second")}>
        Go to Second Page
      </button>
    </div>
  );
}
