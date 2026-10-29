import type { ReactNode } from 'react';

import { describe, scoreTone, type EnumMeta, type Tone } from '../utils/taxonomy';

type StatusChipProps = {
  label: ReactNode;
  tone?: Tone;
  /** Severity-style chips carry a leading dot so they read at a glance in a dense table. */
  dot?: boolean;
  variant?: 'soft' | 'outline';
};

/**
 * A single chip style for every enum in the app. It draws from the theme tokens
 * rather than antd's named colours, so a status looks identical on every page and
 * follows light/dark without per-page colour maps.
 */
export function StatusChip({ label, tone = 'neutral', dot = false, variant = 'soft' }: StatusChipProps) {
  return (
    <span className={`asm-chip asm-chip--${tone} asm-chip--${variant}`}>
      {dot ? <span className="asm-chip-dot" aria-hidden="true" /> : null}
      {label}
    </span>
  );
}

/** Renders a chip from a taxonomy map, falling back to the raw value. */
export function EnumChip({
  map,
  value,
  dot,
  variant
}: {
  map: Record<string, EnumMeta>;
  value: string | undefined;
  dot?: boolean;
  variant?: 'soft' | 'outline';
}) {
  const meta = describe(map, value);
  return <StatusChip label={meta.label} tone={meta.tone} dot={dot} variant={variant} />;
}

/**
 * The risk score is 0-100 points, not a percentage — the old column rendered a
 * bare progress bar suffixed with "%". Showing the number first and tinting the
 * meter by severity band makes rows comparable at a glance.
 */
export function ScoreMeter({ score }: { score: number }) {
  const bounded = Math.min(100, Math.max(0, Math.round(score)));
  return (
    <div className="asm-score">
      <span className={`asm-score-value asm-score-value--${scoreTone(bounded)}`}>{bounded}</span>
      <span className="asm-score-track">
        <span className={`asm-score-fill asm-score-fill--${scoreTone(bounded)}`} style={{ width: `${bounded}%` }} />
      </span>
    </div>
  );
}

/**
 * Confidence is a 0-100 score. The old column drew a bare progress bar with the
 * value hidden, so rows could not be compared or read out loud.
 */
export function ConfidenceMeter({ value }: { value: number }) {
  const bounded = Math.min(100, Math.max(0, Math.round(value)));
  return (
    <div className="asm-score">
      <span className="asm-score-value asm-score-value--info">{bounded}</span>
      <span className="asm-score-track">
        <span className="asm-score-fill asm-score-fill--confidence" style={{ width: `${bounded}%` }} />
      </span>
    </div>
  );
}
