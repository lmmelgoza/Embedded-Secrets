// src/components/MetadataViewer.jsx OR same dir as Second.jsx
import React from "react";

function Section({ title, children }) {
  return (
    <div className="meta-card">
      <div className="meta-title">{title}</div>
      <div>{children}</div>
    </div>
  );
}

function Row({ label, value }) {
  if (value === undefined || value === null || value === "" || Number.isNaN(value)) return null;
  const pretty =
    typeof value === "string" && value.length > 32
      ? <code>{value}</code>
      : typeof value === "boolean"
        ? <span className="meta-badge">{value ? "true" : "false"}</span>
        : typeof value === "object" && !Array.isArray(value)
          ? <code>{JSON.stringify(value)}</code>
          : value;

  return (
    <div className="meta-row">
      <div className="meta-label">{label}</div>
      <div className="meta-value">{pretty}</div>
    </div>
  );
}

const formatBytes = (n) => {
  if (n == null) return "";
  const units = ["B", "kB", "MB", "GB"];
  let i = 0;
  let x = Number(n);
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${x.toFixed(1)} ${units[i]}`;
};

// [num, den] -> "num/den" or dec
const fmtRat = (r, asFraction = true, decimals = 2) => {
  if (!Array.isArray(r) || r.length !== 2) return undefined;
  const [n, d] = r;
  if (d === 0) return undefined;
  return asFraction ? `${n}/${d}` : (n / d).toFixed(decimals);
};

const first = (arr) => (Array.isArray(arr) && arr.length ? arr[0] : undefined);

export default function MetadataViewer({ data }) {
  if (!data) return null;

  // Top-level
  const format = data.format; // "JPEG"
  const mime = data.mime_type || data.mime_guess; // "image/jpeg"
  const mode = data.mode; // "RGB"
  const [width, height] = Array.isArray(data.size) ? data.size : [undefined, undefined];

  const fileBytes = data.file?.size;
  const sha256 = data.file?.sha256;
  const md5 = data.file?.md5;

  // JFIF / DPI / units
  const jfifVersion = Array.isArray(data.info?.jfif_version)
    ? data.info.jfif_version.join(".")
    : data.info?.jfif_version;
  const dpi = Array.isArray(data.info?.dpi) ? `${data.info.dpi[0]} × ${data.info.dpi[1]}` : undefined;
  const jfifUnitMap = { 0: "aspect ratio", 1: "dots per inch", 2: "dots per cm" };
  const jfifUnit = data.info?.jfif_unit != null ? jfifUnitMap[data.info.jfif_unit] || data.info.jfif_unit : undefined;
  const iccPresent = data.icc_profile_present === true ? "yes" : data.icc_profile_present === false ? "no" : undefined;
  const iccDesc = data?.parsed_app2?.icc_profile?.description;

  // EXIF basics (two places: flattened `exif` and deep under jpeg_app_segments.APP1[].parsed.exif_parsed)
  const exifFlat = data.exif || {};
  const app1 = data.jpeg_app_segments?.APP1;
  const deepExif = app1 ? first(app1)?.parsed?.exif_parsed : undefined;

  const exif0th = deepExif?.["0th"] || {};
  const exifExif = deepExif?.Exif || {};

  const make = exifFlat.Make || exif0th.Make;
  const model = exifFlat.Model || exif0th.Model;
  const dateTaken = exifExif.DateTimeOriginal || exifFlat.DateTime || exif0th.DateTime;

  // Exposure data
  const iso = exifExif.ISOSpeedRatings;
  const exposureTime = fmtRat(exifExif.ExposureTime, true); // "1/160"
  const aperture = exifExif.FNumber ? `f/${fmtRat(exifExif.FNumber, false, 1)}` : undefined; // "f/7.1"
  const focalLength = exifExif.FocalLength ? `${fmtRat(exifExif.FocalLength, false, 0)} mm` : undefined;

  // Forensics / thumbnail
  const conflicts = data.forensic?.conflicts;
  const thumbLen = data.forensic?.thumbnail?.thumbnail_len;
  const thumbSha = data.forensic?.thumbnail?.thumbnail_sha256;

  // Marker counts summary
  const markerCounts = data.marker_counts || {};
  const markerList =
    markerCounts && typeof markerCounts === "object"
      ? Object.entries(markerCounts)
          .map(([k, v]) => `${k}: ${v}`)
          .join(", ")
      : undefined;

  return (
    <div>
      {/* SUMMARY */}
      <Section title="Summary">
        <Row label="format" value={format} />
        <Row label="mime type" value={mime} />
        <Row label="dimensions" value={width && height ? `${width} × ${height}` : undefined} />
        <Row label="mode" value={mode} />
        <Row label="file size" value={fileBytes != null ? `${fileBytes} bytes (${formatBytes(fileBytes)})` : undefined} />
        <Row label="sha256" value={sha256} />
        <Row label="md5" value={md5} />
      </Section>

      {/* EXIF */}
      <Section title="EXIF (basic)">
        <Row label="camera make" value={make} />
        <Row label="camera model" value={model} />
        <Row label="date taken" value={dateTaken} />
        <Row label="ISO" value={iso} />
        <Row label="aperture" value={aperture} />
        <Row label="shutter" value={exposureTime} />
        <Row label="focal length" value={focalLength} />
        <Row label="orientation" value={exifFlat.Orientation ?? exif0th.Orientation} />
        <Row label="x resolution" value={exifFlat.XResolution ?? fmtRat(exif0th.XResolution, false, 0)} />
        <Row label="y resolution" value={exifFlat.YResolution ?? fmtRat(exif0th.YResolution, false, 0)} />
        <Row label="software" value={exifFlat.Software ?? exif0th.Software} />
      </Section>

      {/* JFIF / ICC */}
      <Section title="JFIF / ICC">
        <Row label="jfif version" value={jfifVersion} />
        <Row label="dpi" value={dpi} />
        <Row label="jfif unit" value={jfifUnit} />
        <Row label="icc profile present" value={iccPresent} />
        <Row label="icc description" value={iccDesc} />
      </Section>

      {/* Forensics */}
      <Section title="Forensics">
        <Row label="conflicts" value={Array.isArray(conflicts) ? conflicts.join("; ") : undefined} />
        <Row label="thumbnail length" value={thumbLen} />
        <Row label="thumbnail sha256" value={thumbSha} />
      </Section>

      {/* Markers */}
      <Section title="Marker counts">
        <Row label="counts" value={markerList} />
      </Section>
    </div>
  );
}
