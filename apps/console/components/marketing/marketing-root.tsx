import type { ReactNode } from "react";

import { getMarketingContent, type MarketingLocale } from "../../lib/marketing/content";
import styles from "./marketing.module.css";

export function MarketingRoot({
  children,
  locale
}: Readonly<{ children: ReactNode; locale: MarketingLocale }>) {
  const copy = getMarketingContent(locale);
  return (
    <html lang={copy.htmlLang} className={styles.marketingHtml}>
      <body className={styles.marketingBody}>
        <a className={styles.skipLink} href="#main-content">
          {copy.skipLink}
        </a>
        {children}
      </body>
    </html>
  );
}
