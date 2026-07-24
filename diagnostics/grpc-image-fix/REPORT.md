# gRPC image fix diagnostic

Source branch: `codex/api-image-audit-d82a400c`

| Image | Build | Runtime | Trivy HIGH/CRITICAL |
| --- | ---: | ---: | ---: |
| api | 0 | 0 | 0 |
| prometheus | 1 | 125 | 125 |

Exit code `0` means pass. `125` means skipped after build failure.

## api build tail

```text
#21 6.926 go: downloading golang.org/x/mod v0.36.0
#21 ...

#23 [python-builder 9/9] RUN python /workspace/scripts/ci/build_reproducible_wheel.py       --output-dir /wheelhouse/application
#23 7.783 Reproducible wheel verified: /wheelhouse/application/hallu_defense_api-0.1.0-py3-none-any.whl sha256:7310bf414c1e6ca54ea53156ddf1ffa62a15af0c6fe04c601c21a7d2ece85b1a
#23 DONE 9.0s

#24 [stage-2  4/15] COPY --from=python-builder /wheelhouse/runtime /tmp/wheelhouse/runtime
#24 DONE 0.0s

#25 [stage-2  5/15] COPY --from=python-builder /wheelhouse/application /tmp/wheelhouse/application
#25 DONE 0.0s

#26 [stage-2  6/15] COPY scripts/dev/apply_postgres_migrations.py /app/scripts/dev/apply_postgres_migrations.py
#26 DONE 0.0s

#27 [stage-2  7/15] COPY scripts/dev/bootstrap_opensearch_template.py /app/scripts/dev/bootstrap_opensearch_template.py
#27 DONE 0.0s

#28 [stage-2  8/15] COPY scripts/dev/bootstrap_kind_vault.py /app/scripts/dev/bootstrap_kind_vault.py
#28 DONE 0.0s

#29 [stage-2  9/15] COPY infra/rag/pgvector /app/infra/rag/pgvector
#29 DONE 0.0s

#21 [opa-builder 5/5] RUN go mod edit         -require=golang.org/x/crypto@v0.52.0         -require=golang.org/x/net@v0.55.0         -require=golang.org/x/sys@v0.45.0         -require=google.golang.org/grpc@v1.82.1     && go mod tidy     && go mod verify     && test "$(go list -m -f '{{.Version}}' golang.org/x/crypto)" = "v0.52.0"     && test "$(go list -m -f '{{.Version}}' golang.org/x/net)" = "v0.55.0"     && test "$(go list -m -f '{{.Version}}' golang.org/x/sys)" = "v0.45.0"     && test "$(go list -m -f '{{.Version}}' google.golang.org/grpc)" = "v1.82.1"     && CGO_ENABLED=0 go build -tags=opa_no_oci -mod=readonly -trimpath -buildvcs=false         -ldflags="-s -w -X github.com/open-policy-agent/opa/v1/version.Vcs=e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297 -X github.com/open-policy-agent/opa/v1/version.Timestamp=2026-07-02T13:31:31Z -X github.com/open-policy-agent/opa/v1/version.Hostname=reproducible"         -o /out/opa .     && test "$(go version /out/opa)" = "/out/opa: go1.26.5"     && test "$(go version -m /out/opa | awk '$1 == "dep" && $2 == "google.golang.org/grpc" { print $3 }')" = "v1.82.1"     && ! go version -m /out/opa | grep -F "google.golang.org/grpc v1.81.1"     && ! go version -m /out/opa | grep -F "oras.land/oras-go"     && /out/opa version | grep -F "Version: 1.18.2"     && /out/opa version | grep -F "Build Commit: e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297"     && /out/opa version | grep -F "Go Version: go1.26.5"
#21 ...

#30 [stage-2 10/15] COPY infra/rag/opensearch /app/infra/rag/opensearch
#30 DONE 0.0s

#31 [stage-2 11/15] COPY infra/opa/policies /app/infra/opa/policies
#31 DONE 0.0s

#21 [opa-builder 5/5] RUN go mod edit         -require=golang.org/x/crypto@v0.52.0         -require=golang.org/x/net@v0.55.0         -require=golang.org/x/sys@v0.45.0         -require=google.golang.org/grpc@v1.82.1     && go mod tidy     && go mod verify     && test "$(go list -m -f '{{.Version}}' golang.org/x/crypto)" = "v0.52.0"     && test "$(go list -m -f '{{.Version}}' golang.org/x/net)" = "v0.55.0"     && test "$(go list -m -f '{{.Version}}' golang.org/x/sys)" = "v0.45.0"     && test "$(go list -m -f '{{.Version}}' google.golang.org/grpc)" = "v1.82.1"     && CGO_ENABLED=0 go build -tags=opa_no_oci -mod=readonly -trimpath -buildvcs=false         -ldflags="-s -w -X github.com/open-policy-agent/opa/v1/version.Vcs=e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297 -X github.com/open-policy-agent/opa/v1/version.Timestamp=2026-07-02T13:31:31Z -X github.com/open-policy-agent/opa/v1/version.Hostname=reproducible"         -o /out/opa .     && test "$(go version /out/opa)" = "/out/opa: go1.26.5"     && test "$(go version -m /out/opa | awk '$1 == "dep" && $2 == "google.golang.org/grpc" { print $3 }')" = "v1.82.1"     && ! go version -m /out/opa | grep -F "google.golang.org/grpc v1.81.1"     && ! go version -m /out/opa | grep -F "oras.land/oras-go"     && /out/opa version | grep -F "Version: 1.18.2"     && /out/opa version | grep -F "Build Commit: e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297"     && /out/opa version | grep -F "Go Version: go1.26.5"
#21 9.796 all modules verified
#21 50.66 Version: 1.18.2
#21 50.67 Build Commit: e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297
#21 50.68 Go Version: go1.26.5
#21 DONE 51.6s

#32 [stage-2 12/15] COPY --from=opa-builder /out/opa /usr/local/bin/opa
#32 DONE 0.1s

#33 [stage-2 13/15] RUN chmod 0555 /usr/local/bin/opa     && /usr/local/bin/opa version     && /usr/local/bin/opa check --strict /app/infra/opa/policies
#33 0.141 Version: 1.18.2
#33 0.141 Build Commit: e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297
#33 0.141 Build Timestamp: 2026-07-02T13:31:31Z
#33 0.141 Build Hostname: reproducible
#33 0.141 Go Version: go1.26.5
#33 0.141 Platform: linux/amd64
#33 0.141 Rego Version: v1
#33 0.141 WebAssembly: unavailable
#33 DONE 0.2s

#34 [stage-2 14/15] RUN test "$(python --version)" = "Python 3.12.13"     && python -m pip install --no-cache-dir --no-index --no-deps --require-hashes       --find-links=/tmp/wheelhouse/runtime -r /tmp/runtime-linux-py312.lock     && python -m pip install --no-cache-dir --no-index --no-deps       /tmp/wheelhouse/application/hallu_defense_api-0.1.0-py3-none-any.whl     && python -m pip check     && python -c "import hallu_defense; print(hallu_defense.__version__)"     && rm -rf /tmp/wheelhouse /tmp/runtime-linux-py312.lock
#34 2.111 Looking in links: /tmp/wheelhouse/runtime
#34 2.116 Processing /tmp/wheelhouse/runtime/annotated_doc-0.0.4-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 1))
#34 2.123 Processing /tmp/wheelhouse/runtime/annotated_types-0.7.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 5))
#34 2.127 Processing /tmp/wheelhouse/runtime/anyio-4.14.1-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 9))
#34 2.131 Processing /tmp/wheelhouse/runtime/attrs-26.1.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 15))
#34 2.135 Processing /tmp/wheelhouse/runtime/certifi-2026.6.17-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 21))
#34 2.138 Processing /tmp/wheelhouse/runtime/cffi-2.1.0-cp312-cp312-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 25))
#34 2.141 Processing /tmp/wheelhouse/runtime/charset_normalizer-3.4.9-cp312-cp312-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 127))
#34 2.148 Processing /tmp/wheelhouse/runtime/click-8.4.2-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 222))
#34 2.152 Processing /tmp/wheelhouse/runtime/cryptography-48.0.1-cp311-abi3-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 226))
#34 2.169 Processing /tmp/wheelhouse/runtime/fastapi-0.139.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 277))
#34 2.179 Processing /tmp/wheelhouse/runtime/googleapis_common_protos-1.75.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 281))
#34 2.184 Processing /tmp/wheelhouse/runtime/h11-0.16.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 285))
#34 2.187 Processing /tmp/wheelhouse/runtime/httptools-0.8.0-cp312-cp312-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 289))
#34 2.192 Processing /tmp/wheelhouse/runtime/idna-3.18-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 341))
#34 2.196 Processing /tmp/wheelhouse/runtime/jsonschema-4.26.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 347))
#34 2.201 Processing /tmp/wheelhouse/runtime/jsonschema_specifications-2025.9.1-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 351))
#34 2.204 Processing /tmp/wheelhouse/runtime/opentelemetry_api-1.43.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 355))
#34 2.207 Processing /tmp/wheelhouse/runtime/opentelemetry_exporter_otlp_proto_common-1.43.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 363))
#34 2.210 Processing /tmp/wheelhouse/runtime/opentelemetry_exporter_otlp_proto_http-1.43.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 367))
#34 2.213 Processing /tmp/wheelhouse/runtime/opentelemetry_proto-1.43.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 371))
#34 2.216 Processing /tmp/wheelhouse/runtime/opentelemetry_sdk-1.43.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 377))
#34 2.220 Processing /tmp/wheelhouse/runtime/opentelemetry_semantic_conventions-0.64b0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 383))
#34 2.224 Processing /tmp/wheelhouse/runtime/protobuf-7.35.1-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 387))
#34 2.227 Processing /tmp/wheelhouse/runtime/psycopg-3.3.4-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 399))
#34 2.237 Processing /tmp/wheelhouse/runtime/psycopg_binary-3.3.4-cp312-cp312-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 403))
#34 2.251 Processing /tmp/wheelhouse/runtime/psycopg_pool-3.3.1-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 460))
#34 2.254 Processing /tmp/wheelhouse/runtime/pycparser-3.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 464))
#34 2.258 Processing /tmp/wheelhouse/runtime/pydantic-2.13.4-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 468))
#34 2.268 Processing /tmp/wheelhouse/runtime/pydantic_core-2.46.4-cp312-cp312-musllinux_1_1_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 474))
#34 2.278 Processing /tmp/wheelhouse/runtime/python_dotenv-1.2.2-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 596))
#34 2.283 Processing /tmp/wheelhouse/runtime/pyyaml-6.0.3-cp312-cp312-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 600))
#34 2.288 Processing /tmp/wheelhouse/runtime/redis-8.0.1-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 675))
#34 2.296 Processing /tmp/wheelhouse/runtime/referencing-0.37.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 679))
#34 2.299 Processing /tmp/wheelhouse/runtime/requests-2.34.2-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 685))
#34 2.303 Processing /tmp/wheelhouse/runtime/rpds_py-2026.6.3-cp312-cp312-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 691))
#34 2.309 Processing /tmp/wheelhouse/runtime/starlette-1.3.1-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 811))
#34 2.313 Processing /tmp/wheelhouse/runtime/typing_extensions-4.16.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 815))
#34 2.316 Processing /tmp/wheelhouse/runtime/typing_inspection-0.4.2-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 832))
#34 2.319 Processing /tmp/wheelhouse/runtime/urllib3-2.7.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 838))
#34 2.324 Processing /tmp/wheelhouse/runtime/uvicorn-0.51.0-py3-none-any.whl (from -r /tmp/runtime-linux-py312.lock (line 842))
#34 2.329 Processing /tmp/wheelhouse/runtime/uvloop-0.22.1-cp312-cp312-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 846))
#34 2.345 Processing /tmp/wheelhouse/runtime/watchfiles-1.2.0-cp312-cp312-musllinux_1_1_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 897))
#34 2.351 Processing /tmp/wheelhouse/runtime/websockets-16.1-cp312-cp312-musllinux_1_2_x86_64.whl (from -r /tmp/runtime-linux-py312.lock (line 1006))
#34 2.394 Installing collected packages: websockets, watchfiles, uvloop, uvicorn, urllib3, typing-inspection, typing-extensions, starlette, rpds-py, requests, referencing, redis, pyyaml, python-dotenv, pydantic-core, pydantic, pycparser, psycopg-pool, psycopg-binary, psycopg, protobuf, opentelemetry-semantic-conventions, opentelemetry-sdk, opentelemetry-proto, opentelemetry-exporter-otlp-proto-http, opentelemetry-exporter-otlp-proto-common, opentelemetry-api, jsonschema-specifications, jsonschema, idna, httptools, h11, googleapis-common-protos, fastapi, cryptography, click, charset-normalizer, cffi, certifi, attrs, anyio, annotated-types, annotated-doc
#34 6.567 Successfully installed annotated-doc-0.0.4 annotated-types-0.7.0 anyio-4.14.1 attrs-26.1.0 certifi-2026.6.17 cffi-2.1.0 charset-normalizer-3.4.9 click-8.4.2 cryptography-48.0.1 fastapi-0.139.0 googleapis-common-protos-1.75.0 h11-0.16.0 httptools-0.8.0 idna-3.18 jsonschema-4.26.0 jsonschema-specifications-2025.9.1 opentelemetry-api-1.43.0 opentelemetry-exporter-otlp-proto-common-1.43.0 opentelemetry-exporter-otlp-proto-http-1.43.0 opentelemetry-proto-1.43.0 opentelemetry-sdk-1.43.0 opentelemetry-semantic-conventions-0.64b0 protobuf-7.35.1 psycopg-3.3.4 psycopg-binary-3.3.4 psycopg-pool-3.3.1 pycparser-3.0 pydantic-2.13.4 pydantic-core-2.46.4 python-dotenv-1.2.2 pyyaml-6.0.3 redis-8.0.1 referencing-0.37.0 requests-2.34.2 rpds-py-2026.6.3 starlette-1.3.1 typing-extensions-4.16.0 typing-inspection-0.4.2 urllib3-2.7.0 uvicorn-0.51.0 uvloop-0.22.1 watchfiles-1.2.0 websockets-16.1
#34 6.568 WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager, possibly rendering your system unusable. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv. Use the --root-user-action option if you know what you are doing and want to suppress this warning.
#34 8.507 Processing /tmp/wheelhouse/application/hallu_defense_api-0.1.0-py3-none-any.whl
#34 8.516 Installing collected packages: hallu-defense-api
#34 8.867 Successfully installed hallu-defense-api-0.1.0
#34 8.867 WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager, possibly rendering your system unusable. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv. Use the --root-user-action option if you know what you are doing and want to suppress this warning.
#34 10.45 No broken requirements found.
#34 10.51 0.1.0
#34 DONE 10.6s

#35 [stage-2 15/15] RUN adduser -D -u 10001 -s /sbin/nologin appuser     && mkdir -p /run/hallu-defense/kubernetes     && find /app -type d -exec chmod 0555 {} +     && find /app -type f -exec chmod 0444 {} +     && chmod 0555 /usr/local/bin/opa
#35 DONE 0.2s

#36 exporting to image
#36 exporting layers
#36 exporting layers 1.2s done
#36 writing image sha256:04a1b88a5f082e2c4438573f83a9057dd32289b63dbfbf4c433df034ea034622 done
#36 naming to docker.io/library/hallu-defense-api:grpc-fix done
#36 DONE 1.2s
```

## api runtime tail

```text
Version: 1.18.2
Build Commit: e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297
Build Timestamp: 2026-07-02T13:31:31Z
Build Hostname: reproducible
Go Version: go1.26.5
Platform: linux/amd64
Rego Version: v1
WebAssembly: unavailable
```

## api scan tail

```text
2026-07-24T15:12:51Z	INFO	Number of language-specific files	num=2
2026-07-24T15:12:51Z	INFO	[gobinary] Detecting vulnerabilities...
2026-07-24T15:12:51Z	INFO	[python-pkg] Detecting vulnerabilities...
2026-07-24T15:12:51Z	WARN	Using severities from other vendors for some vulnerabilities. Read https://trivy.dev/docs/v0.72/guide/scanner/vulnerability#severity-selection for details.

Report Summary

┌──────────────────────────────────────────────────────────────────────────────────┬────────────┬─────────────────┐
│                                      Target                                      │    Type    │ Vulnerabilities │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ hallu-defense-api:grpc-fix (alpine 3.24.1)                                       │   alpine   │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/annotated_doc-0.0.4.dist-info/METADATA    │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/annotated_types-0.7.0.dist-info/METADATA  │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/anyio-4.14.1.dist-info/METADATA           │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/attrs-26.1.0.dist-info/METADATA           │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/certifi-2026.6.17.dist-info/METADATA      │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/cffi-2.1.0.dist-info/METADATA             │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/charset_normalizer-3.4.9.dist-info/METAD- │ python-pkg │        0        │
│ ATA                                                                              │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/click-8.4.2.dist-info/METADATA            │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/cryptography-48.0.1.dist-info/METADATA    │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/fastapi-0.139.0.dist-info/METADATA        │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/googleapis_common_protos-1.75.0.dist-inf- │ python-pkg │        0        │
│ o/METADATA                                                                       │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/h11-0.16.0.dist-info/METADATA             │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/hallu_defense_api-0.1.0.dist-info/METADA- │ python-pkg │        0        │
│ TA                                                                               │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/httptools-0.8.0.dist-info/METADATA        │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/idna-3.18.dist-info/METADATA              │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/jsonschema-4.26.0.dist-info/METADATA      │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/jsonschema_specifications-2025.9.1.dist-- │ python-pkg │        0        │
│ info/METADATA                                                                    │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/opentelemetry_api-1.43.0.dist-info/METAD- │ python-pkg │        0        │
│ ATA                                                                              │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/opentelemetry_exporter_otlp_proto_common- │ python-pkg │        0        │
│ -1.43.0.dist-info/METADATA                                                       │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/opentelemetry_exporter_otlp_proto_http-1- │ python-pkg │        0        │
│ .43.0.dist-info/METADATA                                                         │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/opentelemetry_proto-1.43.0.dist-info/MET- │ python-pkg │        0        │
│ ADATA                                                                            │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/opentelemetry_sdk-1.43.0.dist-info/METAD- │ python-pkg │        0        │
│ ATA                                                                              │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/opentelemetry_semantic_conventions-0.64b- │ python-pkg │        0        │
│ 0.dist-info/METADATA                                                             │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info/METADATA             │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/protobuf-7.35.1.dist-info/METADATA        │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/psycopg-3.3.4.dist-info/METADATA          │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/psycopg_binary-3.3.4.dist-info/METADATA   │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/psycopg_pool-3.3.1.dist-info/METADATA     │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/pycparser-3.0.dist-info/METADATA          │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/pydantic-2.13.4.dist-info/METADATA        │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/pydantic_core-2.46.4.dist-info/METADATA   │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/python_dotenv-1.2.2.dist-info/METADATA    │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/pyyaml-6.0.3.dist-info/METADATA           │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/redis-8.0.1.dist-info/METADATA            │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/referencing-0.37.0.dist-info/METADATA     │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/requests-2.34.2.dist-info/METADATA        │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/rpds_py-2026.6.3.dist-info/METADATA       │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/starlette-1.3.1.dist-info/METADATA        │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/typing_extensions-4.16.0.dist-info/METAD- │ python-pkg │        0        │
│ ATA                                                                              │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/typing_inspection-0.4.2.dist-info/METADA- │ python-pkg │        0        │
│ TA                                                                               │            │                 │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/urllib3-2.7.0.dist-info/METADATA          │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/uvicorn-0.51.0.dist-info/METADATA         │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/uvloop-0.22.1.dist-info/METADATA          │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/watchfiles-1.2.0.dist-info/METADATA       │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/lib/python3.12/site-packages/websockets-16.1.dist-info/METADATA        │ python-pkg │        0        │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┤
│ usr/local/bin/opa                                                                │  gobinary  │        0        │
└──────────────────────────────────────────────────────────────────────────────────┴────────────┴─────────────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

```

## prometheus build tail

```text
#10 11.73 go: downloading github.com/hashicorp/go-version v1.9.0
#10 11.73 go: downloading github.com/pkg/errors v0.9.1
#10 11.76 go: downloading github.com/hashicorp/go-msgpack v0.5.5
#10 11.78 go: downloading github.com/hashicorp/memberlist v0.5.4
#10 11.81 go: downloading github.com/fxamacker/cbor/v2 v2.9.0
#10 11.84 go: downloading github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.29
#10 11.85 go: downloading github.com/kr/pretty v0.3.1
#10 11.86 go: downloading gopkg.in/inf.v0 v0.9.1
#10 11.88 go: downloading sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730
#10 11.90 go: downloading pgregory.net/rapid v1.2.0
#10 11.94 go: downloading github.com/go-openapi/swag/cmdutils v0.26.0
#10 11.97 go: downloading github.com/go-openapi/swag/conv v0.26.0
#10 11.97 go: downloading github.com/go-openapi/swag/fileutils v0.26.0
#10 12.02 go: downloading github.com/go-openapi/swag/jsonname v0.26.0
#10 12.02 go: downloading github.com/go-openapi/swag/jsonutils v0.26.0
#10 12.09 go: downloading github.com/go-openapi/swag/loading v0.26.0
#10 12.09 go: downloading github.com/go-openapi/swag/mangling v0.26.0
#10 12.13 go: downloading github.com/go-openapi/swag/netutils v0.26.0
#10 12.14 go: downloading github.com/go-openapi/swag/stringutils v0.26.0
#10 12.17 go: downloading github.com/go-openapi/swag/typeutils v0.26.0
#10 12.18 go: downloading github.com/go-openapi/swag/yamlutils v0.26.0
#10 12.29 go: downloading go.opentelemetry.io/auto/sdk v1.2.1
#10 12.29 go: downloading github.com/go-openapi/analysis v0.25.0
#10 12.32 go: downloading github.com/go-openapi/jsonpointer v0.23.1
#10 12.43 go: downloading github.com/go-openapi/loads v0.23.3
#10 12.49 go: downloading github.com/go-openapi/spec v0.22.4
#10 12.83 go: downloading github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
#10 12.98 go: downloading github.com/google/s2a-go v0.1.9
#10 12.98 go: downloading github.com/googleapis/enterprise-certificate-proxy v0.3.15
#10 13.03 go: downloading go.opentelemetry.io/collector/featuregate v1.60.0
#10 13.05 go: downloading go.opentelemetry.io/proto/slim/otlp/collector/profiles/v1development v0.3.0
#10 13.05 go: downloading go.opentelemetry.io/proto/slim/otlp/profiles/v1development v0.3.0
#10 13.09 go: downloading github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatautil v0.154.0
#10 13.10 go: downloading go.opentelemetry.io/collector/component/componentstatus v0.154.0
#10 13.11 go: downloading go.opentelemetry.io/collector/consumer/xconsumer v0.154.0
#10 13.15 go: downloading go.opentelemetry.io/collector/pdata/testdata v0.154.0
#10 13.17 go: downloading go.opentelemetry.io/collector/processor/xprocessor v0.154.0
#10 13.20 go: downloading go.opentelemetry.io/collector/pdata/pprofile v0.154.0
#10 13.22 go: downloading github.com/basgys/goxml2json v1.1.1-0.20231018121955-e66ee54ceaad
#10 13.25 go: downloading github.com/pb33f/jsonpath v0.8.2
#10 13.36 go: downloading github.com/bahlo/generic-list-go v0.2.0
#10 13.36 go: downloading github.com/buger/jsonparser v1.1.2
#10 13.39 go: downloading github.com/hashicorp/go-immutable-radix v1.3.1
#10 13.39 go: downloading github.com/pascaldekloe/goe v0.1.0
#10 13.41 go: downloading github.com/keybase/go-keychain v0.0.1
#10 13.41 go: downloading github.com/google/btree v1.1.3
#10 13.46 go: downloading github.com/hashicorp/go-metrics v0.5.4
#10 13.51 go: downloading github.com/hashicorp/go-msgpack/v2 v2.1.5
#10 13.57 go: downloading github.com/hashicorp/go-sockaddr v1.0.7
#10 13.59 go: downloading github.com/sean-/seed v0.0.0-20170313163322-e2103e2c3529
#10 13.61 go: downloading github.com/x448/float16 v0.8.4
#10 13.63 go: downloading github.com/kr/text v0.2.0
#10 13.63 go: downloading github.com/rogpeppe/go-internal v1.14.1
#10 13.68 go: downloading github.com/go-openapi/jsonreference v0.21.5
#10 13.70 go: downloading github.com/onsi/ginkgo/v2 v2.27.2
#10 13.71 go: downloading github.com/onsi/gomega v1.38.2
#10 13.82 go: downloading golang.org/x/mod v0.36.0
#10 13.87 go: downloading github.com/golang/protobuf v1.5.4
#10 13.87 go: downloading github.com/go-openapi/swag/jsonutils/fixtures_test v0.26.0
#10 13.91 go: downloading github.com/go-openapi/testify/enable/yaml/v2 v2.4.2
#10 13.93 go: downloading google.golang.org/genproto v0.0.0-20260319201613-d00831a3d3e7
#10 13.97 go: downloading github.com/gobwas/glob v0.2.3
#10 13.98 go: downloading github.com/knadh/koanf/maps v0.1.2
#10 13.98 go: downloading github.com/knadh/koanf/providers/confmap v1.0.0
#10 14.00 go: downloading github.com/knadh/koanf/v2 v2.3.5
#10 14.00 go: downloading github.com/bitly/go-simplejson v0.5.1
#10 14.00 go: downloading github.com/hashicorp/golang-lru v0.6.0
#10 14.02 go: downloading github.com/emicklei/go-restful/v3 v3.12.2
#10 14.03 go: downloading github.com/mitchellh/copystructure v1.2.0
#10 14.03 go: downloading gonum.org/v1/gonum v0.17.0
#10 14.05 go: downloading github.com/Masterminds/semver/v3 v3.4.0
#10 14.06 go: downloading github.com/mitchellh/reflectwalk v1.0.2
#10 14.08 go: downloading github.com/go-task/slim-sprig/v3 v3.0.0
#10 14.10 go: downloading github.com/jmespath/go-jmespath v0.4.0
#10 14.21 go: downloading github.com/jmespath/go-jmespath/internal/testify v1.5.1
#10 20.29 all modules verified
#10 20.48 go: downloading github.com/oklog/ulid v1.3.1
#10 20.50 go: downloading github.com/envoyproxy/go-control-plane v0.14.0
#10 20.51 go: downloading cloud.google.com/go v0.123.0
#10 167.7 # github.com/prometheus/prometheus/web/ui
#10 167.7 web/ui/assets_embed.go:24:33: undefined: EmbedFS
#10 ERROR: process "/bin/sh -c go mod edit -require=google.golang.org/grpc@${GRPC_GO_VERSION}     && go mod tidy     && go mod verify     && test \"$(go list -m -f '{{.Version}}' google.golang.org/grpc)\" = \"${GRPC_GO_VERSION}\"     && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false        -ldflags=\"-s -w -X github.com/prometheus/common/version.Version=${PROMETHEUS_VERSION} -X github.com/prometheus/common/version.Revision=${PROMETHEUS_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=${PROMETHEUS_BUILD_DATE}\"        -o /out/prometheus ./cmd/prometheus     && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false        -ldflags=\"-s -w -X github.com/prometheus/common/version.Version=${PROMETHEUS_VERSION} -X github.com/prometheus/common/version.Revision=${PROMETHEUS_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=${PROMETHEUS_BUILD_DATE}\"        -o /out/promtool ./cmd/promtool     && test \"$(go version /out/prometheus)\" = \"/out/prometheus: go1.26.5\"     && test \"$(go version /out/promtool)\" = \"/out/promtool: go1.26.5\"     && test \"$(go version -m /out/prometheus | awk '$1 == \"dep\" && $2 == \"google.golang.org/grpc\" { print $3 }')\" = \"${GRPC_GO_VERSION}\"     && test \"$(go version -m /out/promtool | awk '$1 == \"dep\" && $2 == \"google.golang.org/grpc\" { print $3 }')\" = \"${GRPC_GO_VERSION}\"     && ! go version -m /out/prometheus | grep -F \"google.golang.org/grpc v1.81.1\"     && ! go version -m /out/promtool | grep -F \"google.golang.org/grpc v1.81.1\"     && /out/prometheus --version 2>&1 | grep -F \"prometheus, version 3.13.1\"     && /out/prometheus --version 2>&1 | grep -F \"revision: ${PROMETHEUS_COMMIT}\"     && /out/promtool --version 2>&1 | grep -F \"promtool, version 3.13.1\"" did not complete successfully: exit code: 1
------
 > [prometheus-builder 4/4] RUN go mod edit -require=google.golang.org/grpc@v1.82.1     && go mod tidy     && go mod verify     && test "$(go list -m -f '{{.Version}}' google.golang.org/grpc)" = "v1.82.1"     && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false        -ldflags="-s -w -X github.com/prometheus/common/version.Version=3.13.1 -X github.com/prometheus/common/version.Revision=73ff57ce2b8161059ac7fe5188f03f1c3d22b29a -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=20260710-08:03:47"        -o /out/prometheus ./cmd/prometheus     && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false        -ldflags="-s -w -X github.com/prometheus/common/version.Version=3.13.1 -X github.com/prometheus/common/version.Revision=73ff57ce2b8161059ac7fe5188f03f1c3d22b29a -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=20260710-08:03:47"        -o /out/promtool ./cmd/promtool     && test "$(go version /out/prometheus)" = "/out/prometheus: go1.26.5"     && test "$(go version /out/promtool)" = "/out/promtool: go1.26.5"     && test "$(go version -m /out/prometheus | awk '$1 == "dep" && $2 == "google.golang.org/grpc" { print $3 }')" = "v1.82.1"     && test "$(go version -m /out/promtool | awk '$1 == "dep" && $2 == "google.golang.org/grpc" { print $3 }')" = "v1.82.1"     && ! go version -m /out/prometheus | grep -F "google.golang.org/grpc v1.81.1"     && ! go version -m /out/promtool | grep -F "google.golang.org/grpc v1.81.1"     && /out/prometheus --version 2>&1 | grep -F "prometheus, version 3.13.1"     && /out/prometheus --version 2>&1 | grep -F "revision: 73ff57ce2b8161059ac7fe5188f03f1c3d22b29a"     && /out/promtool --version 2>&1 | grep -F "promtool, version 3.13.1":
14.06 go: downloading github.com/mitchellh/reflectwalk v1.0.2
14.08 go: downloading github.com/go-task/slim-sprig/v3 v3.0.0
14.10 go: downloading github.com/jmespath/go-jmespath v0.4.0
14.21 go: downloading github.com/jmespath/go-jmespath/internal/testify v1.5.1
20.29 all modules verified
20.48 go: downloading github.com/oklog/ulid v1.3.1
20.50 go: downloading github.com/envoyproxy/go-control-plane v0.14.0
20.51 go: downloading cloud.google.com/go v0.123.0
167.7 # github.com/prometheus/prometheus/web/ui
167.7 web/ui/assets_embed.go:24:33: undefined: EmbedFS
------
prometheus.Dockerfile:19
--------------------
  18 |     WORKDIR /src/prometheus
  19 | >>> RUN go mod edit -require=google.golang.org/grpc@${GRPC_GO_VERSION} \
  20 | >>>     && go mod tidy \
  21 | >>>     && go mod verify \
  22 | >>>     && test "$(go list -m -f '{{.Version}}' google.golang.org/grpc)" = "${GRPC_GO_VERSION}" \
  23 | >>>     && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false \
  24 | >>>        -ldflags="-s -w -X github.com/prometheus/common/version.Version=${PROMETHEUS_VERSION} -X github.com/prometheus/common/version.Revision=${PROMETHEUS_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=${PROMETHEUS_BUILD_DATE}" \
  25 | >>>        -o /out/prometheus ./cmd/prometheus \
  26 | >>>     && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false \
  27 | >>>        -ldflags="-s -w -X github.com/prometheus/common/version.Version=${PROMETHEUS_VERSION} -X github.com/prometheus/common/version.Revision=${PROMETHEUS_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=${PROMETHEUS_BUILD_DATE}" \
  28 | >>>        -o /out/promtool ./cmd/promtool \
  29 | >>>     && test "$(go version /out/prometheus)" = "/out/prometheus: go1.26.5" \
  30 | >>>     && test "$(go version /out/promtool)" = "/out/promtool: go1.26.5" \
  31 | >>>     && test "$(go version -m /out/prometheus | awk '$1 == "dep" && $2 == "google.golang.org/grpc" { print $3 }')" = "${GRPC_GO_VERSION}" \
  32 | >>>     && test "$(go version -m /out/promtool | awk '$1 == "dep" && $2 == "google.golang.org/grpc" { print $3 }')" = "${GRPC_GO_VERSION}" \
  33 | >>>     && ! go version -m /out/prometheus | grep -F "google.golang.org/grpc v1.81.1" \
  34 | >>>     && ! go version -m /out/promtool | grep -F "google.golang.org/grpc v1.81.1" \
  35 | >>>     && /out/prometheus --version 2>&1 | grep -F "prometheus, version 3.13.1" \
  36 | >>>     && /out/prometheus --version 2>&1 | grep -F "revision: ${PROMETHEUS_COMMIT}" \
  37 | >>>     && /out/promtool --version 2>&1 | grep -F "promtool, version 3.13.1"
  38 |     
--------------------
ERROR: failed to build: failed to solve: process "/bin/sh -c go mod edit -require=google.golang.org/grpc@${GRPC_GO_VERSION}     && go mod tidy     && go mod verify     && test \"$(go list -m -f '{{.Version}}' google.golang.org/grpc)\" = \"${GRPC_GO_VERSION}\"     && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false        -ldflags=\"-s -w -X github.com/prometheus/common/version.Version=${PROMETHEUS_VERSION} -X github.com/prometheus/common/version.Revision=${PROMETHEUS_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=${PROMETHEUS_BUILD_DATE}\"        -o /out/prometheus ./cmd/prometheus     && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false        -ldflags=\"-s -w -X github.com/prometheus/common/version.Version=${PROMETHEUS_VERSION} -X github.com/prometheus/common/version.Revision=${PROMETHEUS_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=${PROMETHEUS_BUILD_DATE}\"        -o /out/promtool ./cmd/promtool     && test \"$(go version /out/prometheus)\" = \"/out/prometheus: go1.26.5\"     && test \"$(go version /out/promtool)\" = \"/out/promtool: go1.26.5\"     && test \"$(go version -m /out/prometheus | awk '$1 == \"dep\" && $2 == \"google.golang.org/grpc\" { print $3 }')\" = \"${GRPC_GO_VERSION}\"     && test \"$(go version -m /out/promtool | awk '$1 == \"dep\" && $2 == \"google.golang.org/grpc\" { print $3 }')\" = \"${GRPC_GO_VERSION}\"     && ! go version -m /out/prometheus | grep -F \"google.golang.org/grpc v1.81.1\"     && ! go version -m /out/promtool | grep -F \"google.golang.org/grpc v1.81.1\"     && /out/prometheus --version 2>&1 | grep -F \"prometheus, version 3.13.1\"     && /out/prometheus --version 2>&1 | grep -F \"revision: ${PROMETHEUS_COMMIT}\"     && /out/promtool --version 2>&1 | grep -F \"promtool, version 3.13.1\"" did not complete successfully: exit code: 1
```

## prometheus runtime tail

```text
runtime skipped because build failed
```

## prometheus scan tail

```text
scan skipped because build failed
```
