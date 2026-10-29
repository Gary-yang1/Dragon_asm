import type { ReactNode } from 'react';

type PageSectionProps = {
  title?: ReactNode;
  extra?: ReactNode;
  children: ReactNode;
  className?: string;
};

/** A document section; only dialogs and drawers need an elevated surface. */
export function PageSection({ title, extra, children, className = '' }: PageSectionProps) {
  return <section className={`plain-section ${className}`}>
    {(title || extra) && <header className="plain-section-header">
      {title && <h3>{title}</h3>}
      {extra}
    </header>}
    <div className="plain-section-content">{children}</div>
  </section>;
}
