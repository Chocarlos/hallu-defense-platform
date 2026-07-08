# Sistema de defensa contra alucinaciones para LLMs y agentes

Plataforma híbrida y agnóstica de proveedor para verificar respuestas de LLMs, acciones de agentes y claims sobre repositorios usando evidencia real, políticas, sandbox, approvals y auditoría.

Esta primera implementación entrega una vertical slice funcional:

- API `FastAPI` para extracción, clasificación, retrieval, verificación, reparación, tool safety, policy evaluation, sandbox y auditoría.
- Contratos compartidos en JSON Schema, Python/Pydantic y TypeScript.
- SDK TypeScript para integrar apps y agentes.
- Servidor MCP/JSON-RPC por stdio con las tools iniciales.
- Consola DevEx `Next.js` para inspeccionar runs, claims, veredictos y approvals.
- Tests backend y SDK.

## Estructura

```text
apps/
  api/              Backend Python/FastAPI
  console/          Consola DevEx Next.js
packages/
  contracts/        Tipos TS y JSON Schemas públicos
  sdk/              SDK TypeScript
  mcp-server/       Servidor MCP/JSON-RPC stdio
docs/
  adr/              Decisiones de arquitectura
infra/
  docker/           Dockerfiles
```

## Ejecutar backend

```powershell
cd apps/api
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m uvicorn hallu_defense.main:app --reload --port 8000
```

## Ejecutar TypeScript

```powershell
npm install
npm run build
npm run test
npm run dev:console
```

## Flujo end-to-end

`POST /verification/run` ejecuta la ruta completa:

1. Extrae claims atomicos.
2. Clasifica tipo y riesgo.
3. Recupera evidencia.
4. Verifica claim-by-claim.
5. Repara, bloquea o abstiene.
6. Escribe audit ledger con `trace_id`.

Ejemplo minimo:

```json
{
  "tenant_id": "local-dev",
  "message_text": "Los empleados part-time reciben 15 dias de vacaciones pagadas al ano.",
  "documents": [
    {
      "source_ref": "hr-manual-v7",
      "content": "Part-time employees accrue PTO pro rata based on scheduled hours.",
      "authority": "internal"
    }
  ]
}
```

## Seguridad por defecto

- Cada run produce `trace_id`, `tenant_id`, `policy_version`, claims, evidencia, veredictos y decision final.
- Las tool calls de riesgo alto requieren approval.
- El sandbox rechaza comandos no allowlisted y rutas fuera del workspace configurado.
- El modo local permite desarrollo sin OIDC real, pero los contratos ya separan tenant, auditoria y politicas.

