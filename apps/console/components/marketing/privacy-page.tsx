import { ArrowLeft, ShieldCheck } from "lucide-react";

import { getMarketingContent, type MarketingLocale } from "../../lib/marketing/content";
import { Brand } from "./brand";
import styles from "./marketing.module.css";

export function PrivacyPage({
  contactEmail,
  locale
}: Readonly<{ contactEmail: string | null; locale: MarketingLocale }>) {
  const copy = getMarketingContent(locale);
  return (
    <>
      <header className={styles.siteHeader}>
        <nav className={styles.nav} aria-label={copy.navigation.label}>
          <a className={styles.brandLink} href={copy.path} aria-label="Hallu Defense"><Brand /></a>
          <div className={styles.navActions}>
            <a
              className={styles.languageLink}
              href={locale === "es" ? "/en/privacy" : "/privacy"}
              hrefLang={locale === "es" ? "en" : "es"}
              aria-label={copy.navigation.languageLabel}
            >
              {copy.navigation.languageShort}
            </a>
            <a className={styles.consoleLink} href="/console">{copy.navigation.console}</a>
          </div>
        </nav>
      </header>
      <main id="main-content" tabIndex={-1} className={styles.privacyMain}>
        <a className={styles.backLink} href={copy.path}><ArrowLeft aria-hidden="true" size={16} />{copy.privacy.back}</a>
        <p className={styles.eyebrow}>Hallu Defense · privacy.v1</p>
        <h1>{copy.privacy.title}</h1>
        <p className={styles.privacyIntro}>{copy.privacy.intro}</p>
        <div className={styles.privacySections}>
          {copy.privacy.sections.map((section) => (
            <section key={section.title}>
              <h2>{section.title}</h2>
              <p>{section.body}</p>
            </section>
          ))}
          <section className={styles.contactCard}>
            <ShieldCheck aria-hidden="true" size={22} />
            <div>
              <h2>{copy.privacy.contactTitle}</h2>
              {contactEmail === null ? <p>{copy.privacy.contactMissing}</p> : <p>{copy.privacy.contactConfigured} <a href={`mailto:${contactEmail}`}>{contactEmail}</a>.</p>}
            </div>
          </section>
        </div>
        <p className={styles.legalNotice}>{copy.privacy.legalNotice}</p>
      </main>
    </>
  );
}
