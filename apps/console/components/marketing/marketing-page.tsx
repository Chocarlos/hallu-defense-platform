import {
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  FileSearch,
  GitBranch,
  ShieldCheck
} from "lucide-react";

import {
  getMarketingContent,
  SDK_SNIPPET,
  type MarketingLocale
} from "../../lib/marketing/content";
import {
  buildMarketingJsonLd,
  serializeJsonLd
} from "../../lib/marketing/seo";
import { Brand } from "./brand";
import { DemoRequestForm } from "./demo-request-form";
import { PlatformTour } from "./platform-tour";
import { Reveal } from "./reveal";
import styles from "./marketing.module.css";

export function MarketingPage({
  demoRequestsEnabled,
  locale,
  siteOrigin
}: Readonly<{
  demoRequestsEnabled: boolean;
  locale: MarketingLocale;
  siteOrigin: string;
}>) {
  const copy = getMarketingContent(locale);
  const privacyPath = locale === "es" ? "/privacy" : "/en/privacy";
  const jsonLd = serializeJsonLd(buildMarketingJsonLd(locale, siteOrigin));

  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd }} />
      <header className={styles.siteHeader}>
        <nav className={styles.nav} aria-label={copy.navigation.label}>
          <a className={styles.brandLink} href={copy.path} aria-label="Hallu Defense">
            <Brand />
          </a>
          <div className={styles.navLinks}>
            {copy.navigation.items.map((item) => (
              <a key={item.id} href={`#${item.id}`}>
                {item.label}
              </a>
            ))}
          </div>
          <div className={styles.navActions}>
            <a
              className={styles.languageLink}
              href={copy.alternatePath}
              hrefLang={locale === "es" ? "en" : "es"}
              aria-label={copy.navigation.languageLabel}
            >
              {copy.navigation.languageShort}
            </a>
            <a className={styles.consoleLink} href="/console">
              {copy.navigation.console}
            </a>
          </div>
        </nav>
      </header>

      <main id="main-content" tabIndex={-1}>
        <section className={styles.hero} aria-labelledby="hero-title">
          <div className={styles.heroGlow} aria-hidden="true" />
          <div className={styles.heroGrid}>
            <div className={styles.heroCopy}>
              <p className={styles.eyebrow}>{copy.hero.eyebrow}</p>
              <h1 id="hero-title">{copy.hero.title}</h1>
              <p className={styles.heroSubtitle}>{copy.hero.subtitle}</p>
              <div className={styles.heroActions}>
                <a className={styles.primaryButton} href="#demo">
                  {copy.hero.primaryCta}
                  <ArrowRight aria-hidden="true" size={18} />
                </a>
                <a className={styles.secondaryButton} href="#platform">
                  {copy.hero.secondaryCta}
                </a>
              </div>
              <ul className={styles.proofList}>
                {copy.hero.proofPoints.map((point) => (
                  <li key={point}>
                    <CheckCircle2 aria-hidden="true" size={16} />
                    {point}
                  </li>
                ))}
              </ul>
            </div>
            <div className={styles.heroSystem} aria-label={copy.tour.title}>
              <div className={styles.systemHeader}>
                <span className={styles.systemStatus}>
                  <span aria-hidden="true" /> policy.v1
                </span>
                <span>trace_7e4a</span>
              </div>
              <div className={styles.systemClaim}>
                <span>claim_01</span>
                <strong>{copy.tour.steps[0]?.detail}</strong>
              </div>
              <div className={styles.systemFlow} aria-hidden="true">
                <span>claim</span><i /><span>evidence</span><i /><span>policy</span><i /><span>decision</span>
              </div>
              <div className={styles.systemDecision}>
                <ShieldCheck aria-hidden="true" size={22} />
                <span>
                  require_human_review
                  <small>evidence linked · audit ready</small>
                </span>
              </div>
            </div>
          </div>
        </section>

        <section className={styles.section} id="platform" aria-labelledby="platform-title">
          <Reveal>
            <div className={styles.sectionIntro}>
              <p className={styles.eyebrow}>{copy.tour.eyebrow}</p>
              <h2 id="platform-title">{copy.tour.title}</h2>
              <p>{copy.tour.description}</p>
            </div>
            <PlatformTour copy={copy.tour} />
          </Reveal>
        </section>

        <section className={`${styles.section} ${styles.sectionMuted}`} aria-labelledby="scenarios-title">
          <Reveal>
            <div className={styles.sectionIntro}>
              <p className={styles.eyebrow}>{copy.scenarios.eyebrow}</p>
              <h2 id="scenarios-title">{copy.scenarios.title}</h2>
            </div>
            <div className={styles.scenarioGrid}>
              {copy.scenarios.items.map((scenario, index) => {
                const Icon = index === 0 ? FileSearch : index === 1 ? ClipboardCheck : GitBranch;
                return (
                  <article className={styles.scenarioCard} key={scenario.key}>
                    <span className={styles.illustrative}>{copy.scenarios.illustrativeLabel}</span>
                    <Icon aria-hidden="true" size={24} />
                    <h3>{scenario.title}</h3>
                    <p>{scenario.body}</p>
                    <strong>{scenario.outcome}</strong>
                  </article>
                );
              })}
            </div>
          </Reveal>
        </section>

        <section className={styles.section} id="how-it-works" aria-labelledby="workflow-title">
          <Reveal>
            <div className={styles.sectionIntro}>
              <p className={styles.eyebrow}>{copy.workflow.eyebrow}</p>
              <h2 id="workflow-title">{copy.workflow.title}</h2>
            </div>
            <ol className={styles.workflow}>
              {copy.workflow.steps.map((step, index) => (
                <li key={step.title}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <div><h3>{step.title}</h3><p>{step.body}</p></div>
                </li>
              ))}
            </ol>
          </Reveal>
        </section>

        <section className={`${styles.section} ${styles.sectionMuted}`} aria-labelledby="surfaces-title">
          <Reveal>
            <div className={styles.sectionIntro}>
              <p className={styles.eyebrow}>{copy.surfaces.eyebrow}</p>
              <h2 id="surfaces-title">{copy.surfaces.title}</h2>
            </div>
            <div className={styles.surfaceGrid}>
              {copy.surfaces.items.map((surface) => (
                <article key={surface.title}>
                  <span aria-hidden="true" />
                  <h3>{surface.title}</h3>
                  <p>{surface.body}</p>
                </article>
              ))}
            </div>
          </Reveal>
        </section>

        <section className={styles.section} aria-labelledby="integration-title">
          <Reveal className={styles.integrationGrid}>
            <div>
              <p className={styles.eyebrow}>{copy.integrations.eyebrow}</p>
              <h2 id="integration-title">{copy.integrations.title}</h2>
              <p>{copy.integrations.description}</p>
              <ul className={styles.stackList}>
                {copy.integrations.stack.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </div>
            <div className={styles.codeCard}>
              <div><span>{copy.integrations.snippetLabel}</span><span>verification.ts</span></div>
              <pre tabIndex={0}><code>{SDK_SNIPPET}</code></pre>
            </div>
          </Reveal>
        </section>

        <section className={`${styles.section} ${styles.securitySection}`} id="security" aria-labelledby="security-title">
          <Reveal className={styles.securityGrid}>
            <div>
              <p className={styles.eyebrow}>{copy.security.eyebrow}</p>
              <h2 id="security-title">{copy.security.title}</h2>
              <p>{copy.security.description}</p>
            </div>
            <ul className={styles.controlList}>
              {copy.security.controls.map((control) => (
                <li key={control}><ShieldCheck aria-hidden="true" size={18} />{control}</li>
              ))}
            </ul>
          </Reveal>
        </section>

        <section className={styles.section} id="demo" aria-labelledby="demo-title">
          <Reveal className={styles.demoGrid}>
            <div>
              <p className={styles.eyebrow}>{copy.demo.eyebrow}</p>
              <h2 id="demo-title">{copy.demo.title}</h2>
              <p>{copy.demo.description}</p>
            </div>
            <DemoRequestForm copy={copy.demo} enabled={demoRequestsEnabled} locale={locale} />
          </Reveal>
        </section>

        <section className={`${styles.section} ${styles.faqSection}`} id="faq" aria-labelledby="faq-title">
          <Reveal>
            <div className={styles.sectionIntro}>
              <p className={styles.eyebrow}>{copy.faq.eyebrow}</p>
              <h2 id="faq-title">{copy.faq.title}</h2>
            </div>
            <div className={styles.faqList}>
              {copy.faq.items.map((item) => (
                <details key={item.question}>
                  <summary>{item.question}</summary>
                  <p>{item.answer}</p>
                </details>
              ))}
            </div>
          </Reveal>
        </section>
      </main>

      <footer className={styles.footer}>
        <div><Brand /><p>{copy.footer.statement}</p></div>
        <nav aria-label={copy.navigation.label}>
          <a href={privacyPath}>{copy.footer.privacy}</a>
          <a href="/console">{copy.footer.console}</a>
          <a href={copy.alternatePath} hrefLang={locale === "es" ? "en" : "es"}>{copy.navigation.languageShort}</a>
        </nav>
        <small>{copy.footer.launchNote}</small>
      </footer>
    </>
  );
}
