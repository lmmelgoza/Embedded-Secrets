import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { Routes, Route } from "react-router-dom";
import Header from "./Header";
import Home from "./Home";
import Second from "./Second";

function App() {
  return (
    <>
      <Header title="Embedded Secrets" />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/second" element={<Second />} />
      </Routes>
    </>
  )
}

export default App
