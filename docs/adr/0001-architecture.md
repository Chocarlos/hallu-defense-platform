# ADR 0001: Architecture

## Status

Accepted for foundation.

## Context

The platform must defend against hallucinations across document/RAG answers, agent tool calls, and code-agent claims. It must remain hybrid, enterprise-ready, and provider-agnostic.

## Decision

Use a monorepo with:

- Python/FastAPI for the verification plane.
- TypeScript for contracts, SDK, MCP server, and console.
- JSON Schema, Pydantic, TypeScript, and OpenAPI as public contract surfaces.
- Docker Compose for local data plane services.
- Future Kubernetes/Helm/Terraform for deployment.

## Consequences

- Python keeps verification/RAG/evals close to ML and backend tooling.
- TypeScript keeps agent/app integration ergonomic.
- Contract synchronization must be continuously tested.

