/** A share from 0 to 1 drawn with SVG attributes, so no inline style is needed under the enforced CSP. */
export function CoverageBar({ share }: { share: number }) {
  const width = Math.max(0, Math.min(100, share * 100));
  return (
    <svg
      className="coverage-bar"
      viewBox="0 0 100 6"
      preserveAspectRatio="none"
      aria-hidden="true"
      focusable="false"
    >
      <rect className="coverage-bar-track" width="100" height="6" rx="3" />
      <rect className="coverage-bar-fill" width={width} height="6" rx="3" />
    </svg>
  );
}
