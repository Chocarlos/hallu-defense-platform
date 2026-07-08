# ADR 0001: Plataforma hibrida y proveedor-agnostica

## Estado

Aceptada.

## Contexto

El sistema debe validar claims de texto, acciones de agentes y observaciones de repositorio sin depender de un unico proveedor LLM. Tambien debe soportar despliegues locales/on-prem para datos sensibles y una consola operacional.

## Decision

Usaremos:

- Python/FastAPI para el plano de verificacion, RAG, politicas, sandbox y evaluaciones.
- TypeScript/Node para SDK, MCP/adaptadores y consola DevEx.
- Contratos versionados compartidos por JSON Schema, Pydantic y TypeScript.
- Data plane local por defecto y control plane opcional.

## Consecuencias

- La plataforma puede empezar local y crecer a enterprise sin reescribir contratos.
- El backend mantiene cerca las piezas ML/RAG/evals.
- El SDK y MCP quedan ergonomicos para integraciones web y agentic.
- Se acepta duplicacion controlada entre Pydantic y TypeScript hasta incorporar codegen formal.

