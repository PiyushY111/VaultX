import qrcode from 'qrcode-generator';
import { useMemo } from 'react';

/** A QR code drawn as SVG squares (no HTML strings). Rendered on white so any scanner reads it. */
export function QrCode({ text, label }: { text: string; label: string }) {
  const { size, path } = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const count = qr.getModuleCount();
    let d = '';
    for (let row = 0; row < count; row++) {
      for (let col = 0; col < count; col++) if (qr.isDark(row, col)) d += `M${col} ${row}h1v1h-1z`;
    }
    return { size: count, path: d };
  }, [text]);
  return (
    <svg className="qr" viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label}>
      <path d={path} fill="#000" />
    </svg>
  );
}
