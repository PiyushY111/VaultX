// The product's emblem: a keyhole inside a double ring, like a crest on a
// storehouse door. Decorative, so hidden from assistive tech.

const KEYHOLE = 'M50 27a11 11 0 0 1 6.5 19.9L60 72H40l3.5-25.1A11 11 0 0 1 50 27z';

export function Emblem({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 100 100" aria-hidden="true" focusable="false">
      <circle cx="50" cy="50" r="46" fill="none" stroke="currentColor" strokeWidth="3" />
      <circle
        cx="50"
        cy="50"
        r="39"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.25"
        opacity="0.55"
      />
      <path d={KEYHOLE} fill="currentColor" />
    </svg>
  );
}

/** Just the keyhole, for small icons (the Lock button). */
export function KeyholeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="26 22 48 56" aria-hidden="true" focusable="false">
      <path d={KEYHOLE} fill="currentColor" />
    </svg>
  );
}
