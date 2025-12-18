import { useState } from 'react'
import './App.css'
import { Routes, Route } from "react-router-dom";
import Header from "./Header";
import Home from "./Home";
import ReadMetadata from "./ReadMetadata";
import ExtractEmbed from "./Extract_Embed";
import RS_Detector from "./RS_Detector";

function App() {
  return (
    <>
      <Header title="Embedded Secrets" />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/read_metadata" element={<ReadMetadata />} />
        <Route path="/extract_embed" element={<ExtractEmbed />} />
        <Route path = "/rs_detector" element = {<RS_Detector />} />
      </Routes>
    </>
  )
}

export default App
