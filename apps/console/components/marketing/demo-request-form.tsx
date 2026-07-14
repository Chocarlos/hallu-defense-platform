"use client";

import { useRef, useState, type FormEvent } from "react";
import { ArrowLeft, ArrowRight, CheckCircle2, Send } from "lucide-react";

import {
  type MarketingCopy,
  type MarketingLocale
} from "../../lib/marketing/content";
import {
  DEMO_USE_CASES,
  type DemoUseCase
} from "../../lib/demo-request/contracts";
import {
  buildDemoRequestPayload,
  serializeDemoRequest
} from "../../lib/marketing/demo-request";
import styles from "./marketing.module.css";

type SubmissionState = "idle" | "submitting" | "success" | "error";

export function DemoRequestForm({
  copy,
  enabled,
  locale
}: Readonly<{
  copy: MarketingCopy["demo"];
  enabled: boolean;
  locale: MarketingLocale;
}>) {
  const [step, setStep] = useState<1 | 2>(1);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [company, setCompany] = useState("");
  const [useCase, setUseCase] = useState<DemoUseCase>("rag_verification");
  const [consent, setConsent] = useState(false);
  const [website, setWebsite] = useState("");
  const [submissionState, setSubmissionState] = useState<SubmissionState>("idle");
  const [statusMessage, setStatusMessage] = useState("");
  const stepTwoHeading = useRef<HTMLHeadingElement>(null);
  const submissionId = useRef<string | null>(null);

  if (!enabled) {
    return (
      <div className={styles.formDisabled} role="status">
        <span className={styles.statusDot} aria-hidden="true" />
        <p>{copy.disabled}</p>
      </div>
    );
  }

  function continueToDetails(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setStep(2);
    window.requestAnimationFrame(() => stepTwoHeading.current?.focus());
  }

  async function submitRequest(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!consent) {
      setSubmissionState("error");
      setStatusMessage(copy.validationError);
      return;
    }
    submissionId.current ??= crypto.randomUUID();
    let body: string;
    try {
      body = serializeDemoRequest(
        buildDemoRequestPayload({
          submissionId: submissionId.current,
          locale,
          email,
          name,
          company,
          useCase,
          consent,
          website
        })
      );
    } catch {
      setSubmissionState("error");
      setStatusMessage(copy.validationError);
      return;
    }

    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10_000);
    setSubmissionState("submitting");
    setStatusMessage(copy.submitting);
    try {
      const response = await fetch("/demo-request", {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        body,
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal
      });
      if (response.status === 202) {
        setSubmissionState("success");
        setStatusMessage(`${copy.success} ID: ${submissionId.current}`);
        return;
      }
      setSubmissionState("error");
      setStatusMessage(
        response.status === 429
          ? copy.tooManyRequests
          : response.status === 503
            ? copy.unavailable
            : response.status === 400 || response.status === 415 || response.status === 422
              ? copy.validationError
              : copy.genericError
      );
    } catch {
      setSubmissionState("error");
      setStatusMessage(copy.genericError);
    } finally {
      window.clearTimeout(timeout);
    }
  }

  if (submissionState === "success") {
    return (
      <div className={styles.formSuccess} role="status" aria-live="polite">
        <CheckCircle2 aria-hidden="true" size={28} />
        <p>{statusMessage}</p>
      </div>
    );
  }

  return (
    <div className={styles.formCard}>
      <div className={styles.stepIndicator} aria-hidden="true">
        <span className={styles.stepActive} />
        <span className={step === 2 ? styles.stepActive : ""} />
      </div>
      {step === 1 ? (
        <form onSubmit={continueToDetails} className={styles.demoForm}>
          <p className={styles.formStep}>{copy.stepOne}</p>
          <label className={styles.field} htmlFor="demo-email">
            <span>{copy.email}</span>
            <input
              id="demo-email"
              name="email"
              type="email"
              autoComplete="email"
              maxLength={320}
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </label>
          <button className={styles.primaryButton} type="submit">
            {copy.continue}
            <ArrowRight aria-hidden="true" size={17} />
          </button>
        </form>
      ) : (
        <form onSubmit={(event) => void submitRequest(event)} className={styles.demoForm}>
          <h3 ref={stepTwoHeading} tabIndex={-1} className={styles.formStep}>
            {copy.stepTwo}
          </h3>
          <div className={styles.fieldPair}>
            <label className={styles.field} htmlFor="demo-name">
              <span>
                {copy.name} <small>{copy.optional}</small>
              </span>
              <input
                id="demo-name"
                name="name"
                type="text"
                autoComplete="name"
                maxLength={100}
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
            <label className={styles.field} htmlFor="demo-company">
              <span>
                {copy.company} <small>{copy.optional}</small>
              </span>
              <input
                id="demo-company"
                name="organization"
                type="text"
                autoComplete="organization"
                maxLength={120}
                value={company}
                onChange={(event) => setCompany(event.target.value)}
              />
            </label>
          </div>
          <label className={styles.field} htmlFor="demo-use-case">
            <span>{copy.useCase}</span>
            <select
              id="demo-use-case"
              name="use_case"
              value={useCase}
              onChange={(event) => setUseCase(event.target.value as DemoUseCase)}
            >
              {DEMO_USE_CASES.map((value) => (
                <option key={value} value={value}>
                  {copy.useCases[value]}
                </option>
              ))}
            </select>
          </label>
          <div className={styles.honeypot} aria-hidden="true">
            <label htmlFor="demo-website">Website</label>
            <input
              id="demo-website"
              name="website"
              type="text"
              autoComplete="off"
              tabIndex={-1}
              value={website}
              onChange={(event) => setWebsite(event.target.value)}
            />
          </div>
          <label className={styles.consent} htmlFor="demo-consent">
            <input
              id="demo-consent"
              name="consent"
              type="checkbox"
              required
              checked={consent}
              onChange={(event) => setConsent(event.target.checked)}
            />
            <span>
              {copy.consentPrefix}
              <a href={locale === "es" ? "/privacy" : "/en/privacy"}>{copy.consentLink}</a>
              {copy.consentSuffix}
            </span>
          </label>
          <div className={styles.formActions}>
            <button className={styles.textButton} type="button" onClick={() => setStep(1)}>
              <ArrowLeft aria-hidden="true" size={16} />
              {copy.back}
            </button>
            <button
              className={styles.primaryButton}
              type="submit"
              disabled={submissionState === "submitting"}
            >
              <Send aria-hidden="true" size={16} />
              {submissionState === "submitting" ? copy.submitting : submissionState === "error" ? copy.retry : copy.submit}
            </button>
          </div>
          <p
            className={submissionState === "error" ? styles.formError : styles.formStatus}
            role={submissionState === "error" ? "alert" : "status"}
            aria-live="polite"
          >
            {statusMessage}
          </p>
        </form>
      )}
    </div>
  );
}
