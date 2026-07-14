import { ImageResponse } from "next/og";

export const alt =
  "Hallu Defense — evidencia/evidence, política/policy y trazabilidad/traceability";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpenGraphImage() {
  return new ImageResponse(
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        background: "#070B12",
        color: "#F6F7F2",
        padding: "72px 80px",
        fontFamily: "sans-serif"
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "22px", fontSize: 32, fontWeight: 700 }}>
        <div
          style={{
            width: 62,
            height: 62,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            border: "2px solid #45E3C2",
            borderRadius: 18,
            background: "#0D1522",
            color: "#45E3C2",
            fontSize: 30
          }}
        >
          H
        </div>
        Hallu Defense
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "24px", maxWidth: 980 }}>
        <div style={{ fontSize: 76, lineHeight: 1.05, letterSpacing: "-3px", fontWeight: 700 }}>
          Hallu Defense
        </div>
        <div style={{ color: "#AAB7C8", fontSize: 27 }}>
          Evidencia / Evidence · Política / Policy · Trazabilidad / Traceability
        </div>
      </div>
      <div style={{ width: "100%", height: 5, display: "flex", background: "linear-gradient(90deg, #6B8CFF, #45E3C2)" }} />
    </div>,
    size
  );
}
