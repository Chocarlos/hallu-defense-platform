import type { DemoUseCase } from "../demo-request/contracts";

export { DEMO_USE_CASES } from "../demo-request/contracts";
export type { DemoUseCase } from "../demo-request/contracts";

export const MARKETING_LOCALES = ["es", "en"] as const;
export type MarketingLocale = (typeof MARKETING_LOCALES)[number];

export const MARKETING_SECTION_IDS = [
  "platform",
  "how-it-works",
  "security",
  "demo",
  "faq"
] as const;

export const SDK_SNIPPET = `import { HalluDefenseClient } from "@hallu-defense/sdk";

const client = new HalluDefenseClient({
  baseUrl: "http://localhost:8000",
  tenantId: "local-dev"
});

const run = await client.runVerification({
  tenant_id: "local-dev",
  message_text: "La política interna permite esta acción.",
  task_type: "document_qa",
  documents: []
});

console.log(run.trace_id, run.final_decision);`;

export interface MarketingCopy {
  readonly locale: MarketingLocale;
  readonly htmlLang: "es" | "en";
  readonly path: "/" | "/en";
  readonly alternatePath: "/" | "/en";
  readonly metadata: {
    readonly title: string;
    readonly description: string;
  };
  readonly skipLink: string;
  readonly navigation: {
    readonly label: string;
    readonly items: readonly { readonly id: (typeof MARKETING_SECTION_IDS)[number]; readonly label: string }[];
    readonly languageLabel: string;
    readonly languageShort: string;
    readonly console: string;
  };
  readonly hero: {
    readonly eyebrow: string;
    readonly title: string;
    readonly subtitle: string;
    readonly primaryCta: string;
    readonly secondaryCta: string;
    readonly proofPoints: readonly string[];
  };
  readonly tour: {
    readonly eyebrow: string;
    readonly title: string;
    readonly description: string;
    readonly tabsLabel: string;
    readonly pause: string;
    readonly resume: string;
    readonly running: string;
    readonly stopped: string;
    readonly steps: readonly {
      readonly key: "claim" | "evidence" | "policy" | "decision";
      readonly index: string;
      readonly label: string;
      readonly title: string;
      readonly body: string;
      readonly detail: string;
    }[];
  };
  readonly scenarios: {
    readonly eyebrow: string;
    readonly title: string;
    readonly illustrativeLabel: string;
    readonly items: readonly {
      readonly key: "rag" | "tools" | "code";
      readonly title: string;
      readonly body: string;
      readonly outcome: string;
    }[];
  };
  readonly workflow: {
    readonly eyebrow: string;
    readonly title: string;
    readonly steps: readonly { readonly title: string; readonly body: string }[];
  };
  readonly surfaces: {
    readonly eyebrow: string;
    readonly title: string;
    readonly items: readonly { readonly title: string; readonly body: string }[];
  };
  readonly integrations: {
    readonly eyebrow: string;
    readonly title: string;
    readonly description: string;
    readonly stack: readonly string[];
    readonly snippetLabel: string;
  };
  readonly security: {
    readonly eyebrow: string;
    readonly title: string;
    readonly description: string;
    readonly controls: readonly string[];
  };
  readonly demo: {
    readonly eyebrow: string;
    readonly title: string;
    readonly description: string;
    readonly disabled: string;
    readonly stepOne: string;
    readonly stepTwo: string;
    readonly email: string;
    readonly continue: string;
    readonly back: string;
    readonly name: string;
    readonly company: string;
    readonly useCase: string;
    readonly useCases: Readonly<Record<DemoUseCase, string>>;
    readonly consentPrefix: string;
    readonly consentLink: string;
    readonly consentSuffix: string;
    readonly submit: string;
    readonly submitting: string;
    readonly success: string;
    readonly genericError: string;
    readonly validationError: string;
    readonly tooManyRequests: string;
    readonly unavailable: string;
    readonly retry: string;
    readonly optional: string;
  };
  readonly faq: {
    readonly eyebrow: string;
    readonly title: string;
    readonly items: readonly { readonly question: string; readonly answer: string }[];
  };
  readonly footer: {
    readonly statement: string;
    readonly privacy: string;
    readonly console: string;
    readonly launchNote: string;
  };
  readonly privacy: {
    readonly title: string;
    readonly intro: string;
    readonly back: string;
    readonly sections: readonly { readonly title: string; readonly body: string }[];
    readonly contactTitle: string;
    readonly contactConfigured: string;
    readonly contactMissing: string;
    readonly legalNotice: string;
  };
}

export const marketingContent = {
  es: {
    locale: "es",
    htmlLang: "es",
    path: "/",
    alternatePath: "/en",
    metadata: {
      title: "Hallu Defense | Confianza demostrable para LLMs y agentes",
      description: "Verificación basada en evidencia, políticas y ejecución aislada para respuestas de LLMs, RAG, herramientas y agentes de código."
    },
    skipLink: "Saltar al contenido principal",
    navigation: {
      label: "Navegación principal",
      items: [
        { id: "platform", label: "Plataforma" },
        { id: "how-it-works", label: "Cómo funciona" },
        { id: "security", label: "Seguridad" },
        { id: "faq", label: "FAQ" }
      ],
      languageLabel: "Ver sitio en inglés",
      languageShort: "EN",
      console: "Abrir consola"
    },
    hero: {
      eyebrow: "Defensa verificable para sistemas de IA",
      title: "La confianza no se asume. Se demuestra.",
      subtitle: "Hallu Defense conecta cada afirmación y acción con evidencia real, reglas explícitas y una decisión auditable antes de que el riesgo llegue a producción.",
      primaryCta: "Solicitar demo",
      secondaryCta: "Explorar la plataforma",
      proofPoints: ["Evidencia por afirmación", "Aprobación antes de actuar", "Trazabilidad de extremo a extremo"]
    },
    tour: {
      eyebrow: "Tour interactivo",
      title: "De una afirmación a una decisión defendible",
      description: "Recorre el circuito mínimo que convierte una salida plausible en una conclusión sustentada.",
      tabsLabel: "Etapas del circuito de verificación",
      pause: "Pausar recorrido",
      resume: "Reanudar recorrido",
      running: "Recorrido automático activo",
      stopped: "Recorrido automático detenido",
      steps: [
        { key: "claim", index: "01", label: "Afirmación", title: "Extraer lo que debe probarse", body: "La respuesta se separa en afirmaciones atómicas para evitar que una frase parcialmente cierta oculte un error.", detail: "Afirmación: la política permite publicar sin revisión." },
        { key: "evidence", index: "02", label: "Evidencia", title: "Recuperar o ejecutar evidencia", body: "Fuentes autorizadas, resultados de herramientas y SandboxRun aportan señales comprobables y con procedencia.", detail: "Evidencia: la política exige aprobación para riesgo alto." },
        { key: "policy", index: "03", label: "Política", title: "Evaluar contradicciones y riesgo", body: "Reglas versionadas combinan soporte, contradicción, sensibilidad y efectos secundarios antes de decidir.", detail: "Regla: high-risk → require_human_review." },
        { key: "decision", index: "04", label: "Decisión", title: "Permitir, reparar, abstener o bloquear", body: "El sistema devuelve una acción explicable con trace_id, versión de política y evidencia asociada.", detail: "Decisión: bloquear hasta recibir aprobación." }
      ]
    },
    scenarios: {
      eyebrow: "Escenarios",
      title: "Un mismo control, tres riesgos distintos",
      illustrativeLabel: "Escenario ilustrativo",
      items: [
        { key: "rag", title: "Verificación RAG", body: "Contrasta respuestas con fuentes autorizadas, detecta contradicciones y conserva citas por afirmación.", outcome: "Repara o se abstiene cuando la evidencia no alcanza." },
        { key: "tools", title: "Herramientas de alto riesgo", body: "Valida intención, esquema, sensibilidad y efectos antes de ejecutar una acción con impacto.", outcome: "Exige aprobación humana cuando la política lo ordena." },
        { key: "code", title: "Afirmaciones de código", body: "Respalda claims sobre archivos, diffs, tests y builds con resultados deterministas de SandboxRun.", outcome: "No declara éxito sin comando, salida y código de retorno." }
      ]
    },
    workflow: {
      eyebrow: "Cómo funciona",
      title: "Un flujo operativo completo, no una puntuación opaca",
      steps: [
        { title: "Extracción", body: "Divide la salida en afirmaciones atómicas." },
        { title: "Evidencia", body: "Recupera fuentes o ejecuta comprobaciones aisladas." },
        { title: "Contradicciones", body: "Compara soporte, ausencia y conflicto." },
        { title: "Política", body: "Aplica reglas versionadas y contexto de riesgo." },
        { title: "Decisión", body: "Permite, cita, repara, abstiene, revisa o bloquea." },
        { title: "Trazabilidad", body: "Conserva trace_id, evidencia, política y auditoría." }
      ]
    },
    surfaces: {
      eyebrow: "Cobertura",
      title: "Controles coherentes en toda la superficie de IA",
      items: [
        { title: "LLM y RAG", body: "Grounding por afirmación, contradicciones y reparación con citas." },
        { title: "Agentes con herramientas", body: "Validación previa y posterior con aprobación para acciones sensibles." },
        { title: "Agentes de código", body: "Pruebas reproducibles de repositorio, diff, test, build y artefactos." },
        { title: "Gobierno empresarial", body: "Aislamiento por tenant, políticas versionadas, auditoría y observabilidad segura." }
      ]
    },
    integrations: {
      eyebrow: "Integración",
      title: "Entra en el stack que ya operas",
      description: "Una capa de verificación provider-agnostic para equipos que necesitan combinar modelos alojados, ejecución local y contratos abiertos.",
      stack: ["OpenAI-compatible", "Ollama / local", "MCP", "FastAPI", "Docker", "Kubernetes"],
      snippetLabel: "SDK TypeScript"
    },
    security: {
      eyebrow: "Seguridad y gobernanza",
      title: "Diseñado para fallar cerrado donde importa",
      description: "La seguridad es comportamiento ejecutable: límites de tenant, secretos fuera del cliente, egress controlado y aprobación para acciones de alto riesgo.",
      controls: ["OIDC y control de acceso", "Aislamiento de tenants", "PII y secretos redactados", "Sandbox sin red por defecto", "Políticas y aprobaciones versionadas", "Auditoría y métricas de baja cardinalidad"]
    },
    demo: {
      eyebrow: "Demo técnica",
      title: "Cuéntanos qué necesitas demostrar",
      description: "Comparte el caso de uso y prepararemos una conversación técnica. Los datos opcionales pueden omitirse.",
      disabled: "Las solicitudes de demo están desactivadas hasta completar la configuración segura y la revisión legal.",
      stepOne: "Paso 1 de 2: contacto",
      stepTwo: "Paso 2 de 2: contexto y consentimiento",
      email: "Correo de trabajo",
      continue: "Continuar",
      back: "Volver",
      name: "Nombre",
      company: "Empresa",
      useCase: "Caso de uso",
      useCases: { rag_verification: "Verificación RAG", high_risk_tools: "Agentes y herramientas de alto riesgo", code_agents: "Agentes de código y SandboxRun", enterprise_governance: "Gobierno empresarial" },
      consentPrefix: "Acepto el ",
      consentLink: "aviso de privacidad",
      consentSuffix: " y el tratamiento descrito para gestionar esta solicitud.",
      submit: "Solicitar demo",
      submitting: "Enviando solicitud",
      success: "Solicitud recibida. Conserva el identificador mostrado para cualquier seguimiento.",
      genericError: "No pudimos enviar la solicitud. Inténtalo de nuevo con el mismo identificador.",
      validationError: "Revisa los campos y el consentimiento antes de continuar.",
      tooManyRequests: "Se alcanzó el límite de solicitudes. Inténtalo más tarde.",
      unavailable: "La recepción segura de solicitudes no está disponible temporalmente.",
      retry: "Reintentar",
      optional: "opcional"
    },
    faq: {
      eyebrow: "FAQ",
      title: "Preguntas frecuentes",
      items: [
        { question: "¿Hallu Defense reemplaza al modelo?", answer: "No. Se integra como una capa de verificación y control alrededor de modelos, recuperadores y herramientas existentes." },
        { question: "¿Cómo trata una afirmación sin evidencia suficiente?", answer: "La política puede pedir una cita, reparar la respuesta, solicitar aclaración, abstenerse o bloquearla; no convierte ausencia de evidencia en certeza." },
        { question: "¿Puede funcionar con modelos locales?", answer: "Sí. La arquitectura contempla API OpenAI-compatible, Ollama y proveedores locales mediante adaptadores, además de un proveedor mock para pruebas." },
        { question: "¿Cómo verifica afirmaciones sobre código?", answer: "Ejecuta comprobaciones allowlisted en un sandbox y utiliza stdout, stderr, códigos de salida, diffs e inspección estática como evidencia determinista." },
        { question: "¿Está certificado o activado en producción?", answer: "Esta landing no afirma certificación ni activación productiva. La preparación técnica y la evidencia de cada entorno deben evaluarse por separado." }
      ]
    },
    footer: {
      statement: "Evidencia, política y trazabilidad para cada decisión de IA.",
      privacy: "Privacidad",
      console: "Consola",
      launchNote: "La captación real permanece desactivada hasta contar con dominio, secretos y aprobación legal."
    },
    privacy: {
      title: "Aviso de privacidad",
      intro: "Este aviso describe el tratamiento previsto para las solicitudes de demo de Hallu Defense.",
      back: "Volver al inicio",
      sections: [
        { title: "Responsable provisional", body: "Hallu Defense figura provisionalmente como responsable del tratamiento, sujeto a revisión legal antes de activar la captación en producción." },
        { title: "Datos", body: "Se solicita un correo; el nombre y la empresa son opcionales. También se conserva el caso de uso, el consentimiento y la versión privacy.v1. No se solicitan datos sensibles." },
        { title: "Finalidad y base", body: "Los datos se usarán únicamente para gestionar la solicitud y preparar una conversación técnica. El envío requiere consentimiento expreso." },
        { title: "Conservación", body: "El operador del CRM deberá eliminar los leads inactivos a los 90 días. Hallu Defense no debe persistir estos datos localmente." },
        { title: "Destinatarios", body: "La información podrá enviarse al CRM configurado mediante un webhook seguro. No se incluyen IP, user-agent, referrer ni parámetros UTM." },
        { title: "Derechos y seguridad", body: "Las solicitudes de acceso, corrección o eliminación se atenderán mediante el contacto indicado. La transmisión y el acceso deben permanecer protegidos por controles técnicos y organizativos." }
      ],
      contactTitle: "Contacto de privacidad",
      contactConfigured: "Escribe a",
      contactMissing: "El correo de privacidad se publicará después de la revisión legal y antes de activar solicitudes reales.",
      legalNotice: "Documento operativo pendiente de revisión legal; no constituye asesoramiento jurídico."
    }
  },
  en: {
    locale: "en",
    htmlLang: "en",
    path: "/en",
    alternatePath: "/",
    metadata: {
      title: "Hallu Defense | Demonstrable trust for LLMs and agents",
      description: "Evidence-based verification, policy controls, and isolated execution for LLM responses, RAG, tools, and code agents."
    },
    skipLink: "Skip to main content",
    navigation: {
      label: "Primary navigation",
      items: [
        { id: "platform", label: "Platform" },
        { id: "how-it-works", label: "How it works" },
        { id: "security", label: "Security" },
        { id: "faq", label: "FAQ" }
      ],
      languageLabel: "View site in Spanish",
      languageShort: "ES",
      console: "Open console"
    },
    hero: {
      eyebrow: "Verifiable defense for AI systems",
      title: "Trust isn’t assumed. It’s proven.",
      subtitle: "Hallu Defense connects every claim and action to real evidence, explicit policy, and an auditable decision before risk reaches production.",
      primaryCta: "Request a demo",
      secondaryCta: "Explore the platform",
      proofPoints: ["Claim-level evidence", "Approval before action", "End-to-end traceability"]
    },
    tour: {
      eyebrow: "Interactive tour",
      title: "From a claim to a defensible decision",
      description: "Follow the minimum circuit that turns a plausible output into a supported conclusion.",
      tabsLabel: "Verification circuit stages",
      pause: "Pause tour",
      resume: "Resume tour",
      running: "Automatic tour active",
      stopped: "Automatic tour stopped",
      steps: [
        { key: "claim", index: "01", label: "Claim", title: "Extract what must be proven", body: "The response is split into atomic claims so a partially true sentence cannot hide an error.", detail: "Claim: policy allows publishing without review." },
        { key: "evidence", index: "02", label: "Evidence", title: "Retrieve or execute evidence", body: "Authorized sources, tool results, and SandboxRun provide verifiable signals with provenance.", detail: "Evidence: policy requires approval for high risk." },
        { key: "policy", index: "03", label: "Policy", title: "Evaluate contradictions and risk", body: "Versioned rules combine support, contradiction, sensitivity, and side effects before deciding.", detail: "Rule: high-risk → require_human_review." },
        { key: "decision", index: "04", label: "Decision", title: "Allow, repair, abstain, or block", body: "The system returns an explainable action with a trace_id, policy version, and linked evidence.", detail: "Decision: block until approval is granted." }
      ]
    },
    scenarios: {
      eyebrow: "Scenarios",
      title: "One control plane, three distinct risks",
      illustrativeLabel: "Illustrative scenario",
      items: [
        { key: "rag", title: "RAG verification", body: "Checks answers against authorized sources, detects contradictions, and keeps citations per claim.", outcome: "Repairs or abstains when evidence is insufficient." },
        { key: "tools", title: "High-risk tools", body: "Validates intent, schema, sensitivity, and side effects before an impactful action executes.", outcome: "Requires human approval when policy says so." },
        { key: "code", title: "Code claims", body: "Supports claims about files, diffs, tests, and builds with deterministic SandboxRun results.", outcome: "Never declares success without command, output, and exit code." }
      ]
    },
    workflow: {
      eyebrow: "How it works",
      title: "A complete operating flow, not an opaque score",
      steps: [
        { title: "Extraction", body: "Breaks output into atomic claims." },
        { title: "Evidence", body: "Retrieves sources or runs isolated checks." },
        { title: "Contradictions", body: "Compares support, absence, and conflict." },
        { title: "Policy", body: "Applies versioned rules and risk context." },
        { title: "Decision", body: "Allows, cites, repairs, abstains, reviews, or blocks." },
        { title: "Traceability", body: "Keeps trace_id, evidence, policy, and audit." }
      ]
    },
    surfaces: {
      eyebrow: "Coverage",
      title: "Consistent controls across the AI surface",
      items: [
        { title: "LLM and RAG", body: "Claim-level grounding, contradiction detection, and citation-backed repair." },
        { title: "Tool agents", body: "Pre- and post-execution validation with approval for sensitive actions." },
        { title: "Code agents", body: "Reproducible evidence for repositories, diffs, tests, builds, and artifacts." },
        { title: "Enterprise governance", body: "Tenant isolation, versioned policy, audit, and safe observability." }
      ]
    },
    integrations: {
      eyebrow: "Integration",
      title: "Fits the stack you already operate",
      description: "A provider-agnostic verification layer for teams combining hosted models, local execution, and open contracts.",
      stack: ["OpenAI-compatible", "Ollama / local", "MCP", "FastAPI", "Docker", "Kubernetes"],
      snippetLabel: "TypeScript SDK"
    },
    security: {
      eyebrow: "Security and governance",
      title: "Built to fail closed where it matters",
      description: "Security is executable behavior: tenant boundaries, secrets kept off the client, controlled egress, and approval for high-risk actions.",
      controls: ["OIDC and access control", "Tenant isolation", "PII and secret redaction", "Network-denied sandbox by default", "Versioned policy and approvals", "Audit and low-cardinality metrics"]
    },
    demo: {
      eyebrow: "Technical demo",
      title: "Tell us what you need to prove",
      description: "Share the use case and we will prepare a technical conversation. Optional details may be omitted.",
      disabled: "Demo requests are disabled until secure configuration and legal review are complete.",
      stepOne: "Step 1 of 2: contact",
      stepTwo: "Step 2 of 2: context and consent",
      email: "Work email",
      continue: "Continue",
      back: "Back",
      name: "Name",
      company: "Company",
      useCase: "Use case",
      useCases: { rag_verification: "RAG verification", high_risk_tools: "High-risk agents and tools", code_agents: "Code agents and SandboxRun", enterprise_governance: "Enterprise governance" },
      consentPrefix: "I accept the ",
      consentLink: "privacy notice",
      consentSuffix: " and the described processing required to handle this request.",
      submit: "Request a demo",
      submitting: "Sending request",
      success: "Request received. Keep the displayed identifier for any follow-up.",
      genericError: "We could not send the request. Try again with the same identifier.",
      validationError: "Review the fields and consent before continuing.",
      tooManyRequests: "The request limit has been reached. Try again later.",
      unavailable: "Secure request intake is temporarily unavailable.",
      retry: "Retry",
      optional: "optional"
    },
    faq: {
      eyebrow: "FAQ",
      title: "Frequently asked questions",
      items: [
        { question: "Does Hallu Defense replace the model?", answer: "No. It integrates as a verification and control layer around existing models, retrievers, and tools." },
        { question: "What happens when a claim lacks sufficient evidence?", answer: "Policy can require a citation, repair the response, ask for clarification, abstain, or block it; missing evidence is never converted into certainty." },
        { question: "Can it work with local models?", answer: "Yes. The architecture supports OpenAI-compatible APIs, Ollama, and local providers through adapters, plus a deterministic mock provider for testing." },
        { question: "How are claims about code verified?", answer: "Allowlisted checks run in a sandbox, using stdout, stderr, exit codes, diffs, and static inspection as deterministic evidence." },
        { question: "Is it certified or activated in production?", answer: "This landing page makes no certification or production-activation claim. Technical readiness and evidence must be evaluated for each environment." }
      ]
    },
    footer: {
      statement: "Evidence, policy, and traceability for every AI decision.",
      privacy: "Privacy",
      console: "Console",
      launchNote: "Real lead intake remains disabled until domain, secrets, and legal approval are available."
    },
    privacy: {
      title: "Privacy notice",
      intro: "This notice describes the intended processing for Hallu Defense demo requests.",
      back: "Back to home",
      sections: [
        { title: "Provisional controller", body: "Hallu Defense is provisionally identified as the controller, subject to legal review before production lead intake is activated." },
        { title: "Data", body: "An email is required; name and company are optional. The use case, consent, and privacy.v1 version are also retained. Sensitive data is not requested." },
        { title: "Purpose and basis", body: "Data is used only to handle the request and prepare a technical conversation. Submission requires explicit consent." },
        { title: "Retention", body: "The CRM operator must delete inactive leads after 90 days. Hallu Defense must not persist this data locally." },
        { title: "Recipients", body: "Information may be sent to the configured CRM through a secure webhook. IP, user-agent, referrer, and UTM parameters are excluded." },
        { title: "Rights and security", body: "Requests for access, correction, or deletion will be handled through the listed contact. Transmission and access must remain protected by technical and organizational controls." }
      ],
      contactTitle: "Privacy contact",
      contactConfigured: "Write to",
      contactMissing: "The privacy email will be published after legal review and before real requests are enabled.",
      legalNotice: "Operational draft pending legal review; it is not legal advice."
    }
  }
} as const satisfies Record<MarketingLocale, MarketingCopy>;

export function getMarketingContent(locale: MarketingLocale): MarketingCopy {
  return marketingContent[locale];
}
