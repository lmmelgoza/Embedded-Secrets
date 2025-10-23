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

function JpegAppSegments({ meta }) {
  const segs = meta?.jpeg_app_segments;
  if (!segs) return null;
  return (
    <section>
      <h3>JPEG APP segments</h3>
      {Object.entries(segs).map(([name, list]) => (
        <div key={name}>
          <h4>{name}</h4>
          {list.map((e, i) => (
            <div key={i} style={{ paddingLeft: 12, marginBottom: 8 }}>
              <div>
                <strong>offset:</strong> {e.offset} &nbsp;
                <strong>length:</strong> {e.length} &nbsp;
                <strong>type:</strong> {e.type || "-"}
              </div>
              {e.payload_head_parsed && (
                <pre style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
                  {JSON.stringify(e.payload_head_parsed, null, 2 )}
                </pre>
              )}
              </div>
          ))}
        </div>
      ))}
    </section>
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

  // replace your isPNG with a stricter version
const isPNG =
  data?.format === "PNG" ||
  /image\/png/i.test(data?.mime_type || data?.mime_guess || "") ||
  !!data?.ihdr ||
  typeof data?.iend_index === "number";

  
  const format = data.format || (isPNG ? "PNG" : undefined); //JPEG or PNG
  const mime = data.mime_type || data.mime_guess || (isPNG ? "image/png" : undefined); // "image/jpeg"
  const mode = data.mode; // "RGB"
  const [width, height] = Array.isArray(data.size) ? data.size : [undefined, undefined];

  const fileBytes = (data.file && data.file.size != null) ? data.file.size : data.file_size;
  const sha256 = data.file?.sha256;
  const md5 = data.file?.md5;

  // JFIF / DPI / units (JPEG)
  const jfifVersion = Array.isArray(data.info?.jfif_version)
    ? data.info.jfif_version.join(".")
    : data.info?.jfif_version;
  const dpi = Array.isArray(data.info?.dpi) ? `${data.info.dpi[0]} × ${data.info.dpi[1]}` : undefined;
  const jfifUnitMap = { 0: "aspect ratio", 1: "dots per inch", 2: "dots per cm" };
  const jfifUnit = data.info?.jfif_unit != null ? jfifUnitMap[data.info.jfif_unit] || data.info.jfif_unit : undefined;
  const iccPresent = data.icc_profile_present === true ? "yes" : data.icc_profile_present === false ? "no" : undefined;
  const iccDesc = data?.parsed_app2?.icc_profile?.description;

  // EXIF basics (JPEG)
  const exifFlat = data.exif || {};
  const app1 = data.jpeg_app_segments?.APP1;
  const deepExif = app1 ? first(app1)?.parsed?.exif_parsed : undefined;

  const exif0th = deepExif?.["0th"] || {};
  const exifExif = deepExif?.Exif || {};

  const make = exifFlat.Make || exif0th.Make;
  const model = exifFlat.Model || exif0th.Model;
  const dateTaken = exifExif.DateTimeOriginal || exifFlat.DateTime || exif0th.DateTime;

  // Exposure data (JPEG)
  const iso = isPNG ? exifFlat.ISOSpeedRatings : exifExif.ISOSpeedRatings;
  const exposureTime = isPNG
    ? fmtRat(exifFlat.ExposureTime, true)
    : fmtRat(exifExif.ExposureTime, true); 
  const aperture = isPNG
    ? (exifFlat.FNumber ? `f/${fmtRat(exifFlat.FNumber, false, 1)}` : undefined)
    : (exifExif.FNumber ? `f/${fmtRat(exifExif.FNumber, false, 1)}` : undefined); // "f/7.1"
  const focalLength = isPNG
    ? (exifFlat.FocalLength ? `${fmtRat(exifFlat.FocalLength, false, 0)} mm` : undefined)
    : (exifExif.FocalLength ? `${fmtRat(exifExif.FocalLength, false, 0)} mm` : undefined);

  // Forensics / thumbnail (JPEG)
  const conflicts = data.forensic?.conflicts;
  const thumbLen = data.forensic?.thumbnail?.thumbnail_len;
  const thumbSha = data.forensic?.thumbnail?.thumbnail_sha256;

  // Marker counts summary (JPEG uses marker_counts, PNG uses chunk_counts)
  const markerCounts = data.marker_counts || {};
  const markerList =
    markerCounts && typeof markerCounts === "object"
      ? Object.entries(markerCounts)
          .map(([k, v]) => `${k}: ${v}`)
          .join(", ")
      : undefined;

  const pngForensic = isPNG ? data.forensic || {} : {};
  const pngMarkerSummary = isPNG && data.markers
    ? Object.entries(data.markers)
        .filter(([, v]) => v && v.present)
        .map(([k, v]) => (v.count > 1 ? `${k}: ${v.count}` : k))
        .join(", ")
    : undefined;

  const ihdr = isPNG ? data.ihdr : null;

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

      {/* EXIF (JPEG) */}
      {!isPNG && (
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
      )}

      {/* EXIF (PNG) */}
      {isPNG && Object.keys(exifFlat).length > 0 && (
        <Section title="EXIF (basic)">
          <Row label = "camera make" value={exifFlat.Make} />
          <Row label = "camera model" value={exifFlat.Model} />
          <Row label = "date taken" value={dateTaken} />
          <Row label = "ISO" value={iso} />
          <Row label = "aperture" value={aperture} />
          <Row label = "shutter" value={exposureTime} />
          <Row label = "focal length" value={focalLength} />
          <Row label = "orientation" value={exifFlat.Orientation} />
          <Row label = "x resolution" value={fmtRat(exifFlat.XResolution, false, 0)} />
          <Row label = "y resolution" value={fmtRat(exifFlat.YResolution, false, 0)} />
          <Row label = "software" value={exifFlat.Software} />
        </Section>
      )}

      {/* JFIF / ICC (JPEG) */}
      {!isPNG && (
        <Section title="JFIF / ICC">
          <Row label="jfif version" value={jfifVersion} />
          <Row label="dpi" value={dpi} />
          <Row label="jfif unit" value={jfifUnit} />
          <Row label="icc profile present" value={iccPresent} />
          <Row label="icc description" value={iccDesc} />
        </Section>
      )}
      {/* JPEG APP segments (shows payload_head_parsed) */}
      {/*!isPNG && <JpegAppSegments meta={data} />*/}

      {/* Forensics (JPEG)*/}
      {!isPNG && (
        <Section title="JPG Forensics">
          <Row label="conflicts" value={Array.isArray(conflicts) ? conflicts.join("; ") : undefined} />
          <Row label="thumbnail length" value={thumbLen} />
          <Row label="thumbnail sha256" value={thumbSha} />
        </Section>
      )}

      {/* Forensic (PNG) */}
      {isPNG && (
        <Section title="PNG Forensics">
          <Row label = "valid signature" value={data.valid_signature} />
          <Row label ="IEND index" value={data.iend_index} />
          <Row label ="trailing bytes after IEND" value={data.trailing_bytes} />
          <Row label = "APNG present" value={pngForensic.is_apng} />
          <Row label = "ICC profile present" value={pngForensic.icc_profile_present} />
          <Row label ="pixel density present" value={pngForensic.pixel_density_present} />
          <Row label ="timestamp present" value={pngForensic.timestamp_present} /> 
          <Row label ="text chunks present" value={pngForensic.text_chunks_present} />
          <Row label ="unknown ancillary chunks" value={Array.isArray(data.unknown_ancillary_chunks) ? data.unknown_ancillary_chunks.length : undefined} />     
          <Row label ="duplicates" value={data.duplicates} />
          {/*<Row label ="CRC errors" value={Array.isArray(pngForensic.Forensic.crc_errors) ? pngForensic.crc_errors.length : undefined} />*/}
          <Row label ="reserved bit violations" value={Array.isArray(pngForensic.reserved_bit_violations) ? pngForensic.reserved_bit_violations.length : undefined} />
        </Section>
      )}

      {/* Markers/Chunks */}
      {isPNG && (
        <Section title="PNG Markers">
          <Row label="present markers" value = {pngMarkerSummary} />
        </Section>
      )}

      {/* Markers */}
      <Section title={isPNG ? "Chunk counts" : "Marker counts"}>
        <Row label="counts" value={markerList} />
      </Section>
    </div>
  );
}
