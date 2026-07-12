-- Audit completion integrity, exactly-once keys, and bounded export indexes.
--
-- This migration backfills completion_path only for an unequivocal legacy
-- run/completion pair. One trace can legitimately have v1, v2, and replay
-- completions, so ambiguous history fails closed instead of being guessed. New
-- completion writes always provide the column. Every replacement is transactional;
-- re-running this file repairs a drifted named constraint/index definition without
-- deleting audit rows. Invalid legacy envelopes or duplicate idempotency keys fail
-- closed during validation/index creation and require operator investigation.

ALTER TABLE audit_runs
    ADD COLUMN IF NOT EXISTS completion_path text;

ALTER TABLE audit_runs
    ALTER COLUMN completion_path TYPE text USING completion_path::text,
    ALTER COLUMN completion_path DROP DEFAULT,
    ALTER COLUMN completion_path DROP NOT NULL;

-- Pre-013 replay success wrote a run plus verification_replay provenance but no
-- verification_completed event. Reconcile only the exact legacy shape identified
-- by input.replay_of/source_trace_id; every other partial or ambiguous triple fails.
DO $audit_replay_backfill$
DECLARE
    replay_row record;
    duplicate_group_count bigint;
    completed_run_count bigint;
    matching_completed_run_count bigint;
    legacy_run_count bigint;
    completion_count bigint;
    matching_completion_count bigint;
    updated_run_count bigint;
    migrated_event_id text;
BEGIN
    SELECT count(*)
    INTO duplicate_group_count
    FROM (
        SELECT tenant_id, trace_id
        FROM audit_events
        WHERE payload ->> 'event_type' = 'verification_replay'
        GROUP BY tenant_id, trace_id
        HAVING count(*) <> 1
    ) AS duplicate_replays;

    IF duplicate_group_count > 0 THEN
        RAISE EXCEPTION
            'audit replay legacy reconciliation found duplicate provenance groups (groups=%)',
            duplicate_group_count
            USING ERRCODE = '23514';
    END IF;

    FOR replay_row IN
        SELECT
            id,
            tenant_id,
            trace_id,
            created_at,
            payload,
            payload #>> '{metadata,source_trace_id}' AS source_trace_id,
            payload #>> '{metadata,source_final_decision}' AS source_final_decision,
            payload #>> '{metadata,replay_final_decision}' AS replay_final_decision
        FROM audit_events
        WHERE payload ->> 'event_type' = 'verification_replay'
        ORDER BY id
    LOOP
        IF (
            replay_row.payload
                @> '{"method":"POST","path":"/verification/replay","status_code":200,"outcome":"success"}'::jsonb
            AND replay_row.tenant_id = btrim(replay_row.tenant_id)
            AND replay_row.tenant_id <> ''
            AND replay_row.trace_id ~ '^tr_[A-Za-z0-9_-]{8,80}$'
            AND replay_row.source_trace_id ~ '^tr_[A-Za-z0-9_-]{8,80}$'
            AND replay_row.source_final_decision IN (
                'allow', 'repaired', 'abstained', 'blocked', 'require_human_review'
            )
            AND replay_row.replay_final_decision IN (
                'allow', 'repaired', 'abstained', 'blocked', 'require_human_review'
            )
            AND jsonb_typeof(replay_row.payload #> '{metadata,decision_changed}') = 'boolean'
            AND replay_row.payload #> '{metadata,decision_changed}' =
                CASE
                    WHEN replay_row.source_final_decision
                         <> replay_row.replay_final_decision
                    THEN 'true'::jsonb
                    ELSE 'false'::jsonb
                END
            AND replay_row.payload -> 'metadata' = jsonb_build_object(
                'source_trace_id', replay_row.source_trace_id,
                'source_final_decision', replay_row.source_final_decision,
                'replay_final_decision', replay_row.replay_final_decision,
                'decision_changed', replay_row.payload #> '{metadata,decision_changed}'
            )
        ) IS NOT TRUE THEN
            RAISE EXCEPTION
                'audit replay legacy reconciliation found an invalid provenance envelope'
                USING ERRCODE = '23514';
        END IF;

        SELECT
            count(*) FILTER (
                WHERE completion_path = '/verification/replay'
            ),
            count(*) FILTER (
                WHERE completion_path = '/verification/replay'
                  AND payload #>> '{input,replay_of}' = replay_row.source_trace_id
                  AND payload ->> 'final_decision' = replay_row.replay_final_decision
            ),
            count(*) FILTER (
                WHERE completion_path IS NULL
                  AND payload #>> '{input,replay_of}' = replay_row.source_trace_id
                  AND payload ->> 'final_decision' = replay_row.replay_final_decision
            )
        INTO completed_run_count, matching_completed_run_count, legacy_run_count
        FROM audit_runs
        WHERE tenant_id = replay_row.tenant_id
          AND trace_id = replay_row.trace_id;

        SELECT
            count(*) FILTER (
                WHERE payload ->> 'event_type' = 'verification_completed'
                  AND payload ->> 'path' = '/verification/replay'
            ),
            count(*) FILTER (
                WHERE payload ->> 'event_type' = 'verification_completed'
                  AND payload ->> 'path' = '/verification/replay'
                  AND payload #>> '{metadata,final_decision}' =
                      replay_row.replay_final_decision
            )
        INTO completion_count, matching_completion_count
        FROM audit_events
        WHERE tenant_id = replay_row.tenant_id
          AND trace_id = replay_row.trace_id;

        IF (
            completed_run_count = 1
            AND matching_completed_run_count = 1
            AND legacy_run_count = 0
            AND completion_count = 1
            AND matching_completion_count = 1
        ) THEN
            CONTINUE;
        END IF;

        IF NOT (
            completed_run_count = 0
            AND matching_completed_run_count = 0
            AND legacy_run_count = 1
            AND completion_count IN (0, 1)
            AND matching_completion_count = completion_count
        ) THEN
            RAISE EXCEPTION
                'audit replay legacy reconciliation found an orphaned or ambiguous triple'
                USING ERRCODE = '23514';
        END IF;

        UPDATE audit_runs
        SET completion_path = '/verification/replay'
        WHERE tenant_id = replay_row.tenant_id
          AND trace_id = replay_row.trace_id
          AND completion_path IS NULL
          AND payload #>> '{input,replay_of}' = replay_row.source_trace_id
          AND payload ->> 'final_decision' = replay_row.replay_final_decision;
        GET DIAGNOSTICS updated_run_count = ROW_COUNT;
        IF updated_run_count <> 1 THEN
            RAISE EXCEPTION
                'audit replay legacy reconciliation did not update exactly one run'
                USING ERRCODE = '23514';
        END IF;

        IF completion_count = 0 THEN
            migrated_event_id := 'evt_migrated_completion_' || replay_row.id::text;
            IF EXISTS (
                SELECT 1
                FROM audit_events
                WHERE tenant_id = replay_row.tenant_id
                  AND event_id = migrated_event_id
            ) THEN
                RAISE EXCEPTION
                    'audit replay legacy reconciliation event id already exists'
                    USING ERRCODE = '23514';
            END IF;

            INSERT INTO audit_events (
                tenant_id,
                trace_id,
                event_id,
                payload,
                created_at
            ) VALUES (
                replay_row.tenant_id,
                replay_row.trace_id,
                migrated_event_id,
                jsonb_build_object(
                    'event_id', migrated_event_id,
                    'trace_id', replay_row.trace_id,
                    'tenant_id', replay_row.tenant_id,
                    'event_type', 'verification_completed',
                    'method', 'POST',
                    'path', '/verification/replay',
                    'status_code', 200,
                    'outcome', 'success',
                    'metadata', jsonb_build_object(
                        'final_decision', replay_row.replay_final_decision
                    ),
                    'created_at', to_jsonb(replay_row.created_at)
                ),
                replay_row.created_at
            );
        END IF;
    END LOOP;
END;
$audit_replay_backfill$;

-- Upgrade compatibility for ledgers written before completion_path existed.
-- A legacy trace is backfilled only when its remaining unmatched evidence is
-- unequivocal: one NULL-path run and one completion event with an allowed path.
-- Existing non-NULL pairs are excluded so a raw idempotent rerun is a no-op.
DO $audit_history_backfill$
DECLARE
    invalid_group_count bigint;
BEGIN
    WITH unmatched_events AS (
        SELECT
            audit_event.id,
            audit_event.tenant_id,
            audit_event.trace_id,
            audit_event.payload ->> 'path' AS completion_path
        FROM audit_events AS audit_event
        WHERE audit_event.payload ->> 'event_type' = 'verification_completed'
          AND NOT EXISTS (
              SELECT 1
              FROM audit_runs AS completed_run
              WHERE completed_run.tenant_id = audit_event.tenant_id
                AND completed_run.trace_id = audit_event.trace_id
                AND completed_run.completion_path = audit_event.payload ->> 'path'
          )
    ),
    candidate_keys AS (
        -- NULL-path runs without a completion are legitimate historical/import
        -- records. Only an unmatched completion event requires pair recovery.
        SELECT DISTINCT tenant_id, trace_id
        FROM unmatched_events
    ),
    candidate_cardinality AS (
        SELECT
            candidate.tenant_id,
            candidate.trace_id,
            (
                SELECT count(*)
                FROM audit_runs AS legacy_run
                WHERE legacy_run.tenant_id = candidate.tenant_id
                  AND legacy_run.trace_id = candidate.trace_id
                  AND legacy_run.completion_path IS NULL
            ) AS run_count,
            (
                SELECT count(*)
                FROM unmatched_events AS completion
                WHERE completion.tenant_id = candidate.tenant_id
                  AND completion.trace_id = candidate.trace_id
            ) AS event_count,
            (
                SELECT min(completion.completion_path)
                FROM unmatched_events AS completion
                WHERE completion.tenant_id = candidate.tenant_id
                  AND completion.trace_id = candidate.trace_id
            ) AS completion_path
        FROM candidate_keys AS candidate
    )
    SELECT count(*)
    INTO invalid_group_count
    FROM candidate_cardinality
    WHERE run_count <> 1
       OR event_count <> 1
       OR completion_path IS NULL
       OR completion_path NOT IN (
           '/verification/run',
           '/v2/verification/run',
           '/verification/replay'
       );

    IF invalid_group_count > 0 THEN
        RAISE EXCEPTION
            'audit completion legacy backfill is orphaned, ambiguous, or has an invalid path (groups=%)',
            invalid_group_count
            USING ERRCODE = '23514';
    END IF;

    WITH unmatched_events AS (
        SELECT
            audit_event.tenant_id,
            audit_event.trace_id,
            min(audit_event.payload ->> 'path') AS completion_path
        FROM audit_events AS audit_event
        WHERE audit_event.payload ->> 'event_type' = 'verification_completed'
          AND NOT EXISTS (
              SELECT 1
              FROM audit_runs AS completed_run
              WHERE completed_run.tenant_id = audit_event.tenant_id
                AND completed_run.trace_id = audit_event.trace_id
                AND completed_run.completion_path = audit_event.payload ->> 'path'
          )
        GROUP BY audit_event.tenant_id, audit_event.trace_id
        HAVING count(*) = 1
    )
    UPDATE audit_runs AS legacy_run
    SET completion_path = completion.completion_path
    FROM unmatched_events AS completion
    WHERE legacy_run.tenant_id = completion.tenant_id
      AND legacy_run.trace_id = completion.trace_id
      AND legacy_run.completion_path IS NULL;

    -- Validate cross-table parity after backfill. This catches legacy or drifted
    -- orphan pairs and duplicates before any uniqueness index is replaced.
    WITH run_groups AS (
        SELECT
            tenant_id,
            trace_id,
            completion_path,
            count(*) AS row_count,
            min(payload ->> 'final_decision') AS final_decision
        FROM audit_runs
        WHERE completion_path IS NOT NULL
        GROUP BY tenant_id, trace_id, completion_path
    ),
    event_groups AS (
        SELECT
            tenant_id,
            trace_id,
            payload ->> 'path' AS completion_path,
            count(*) AS row_count,
            min(payload #>> '{metadata,final_decision}') AS final_decision
        FROM audit_events
        WHERE payload ->> 'event_type' = 'verification_completed'
        GROUP BY tenant_id, trace_id, payload ->> 'path'
    ),
    pair_keys AS (
        SELECT tenant_id, trace_id, completion_path FROM run_groups
        UNION
        SELECT tenant_id, trace_id, completion_path FROM event_groups
    )
    SELECT count(*)
    INTO invalid_group_count
    FROM pair_keys AS pair
    LEFT JOIN run_groups AS completed_run
        ON completed_run.tenant_id = pair.tenant_id
       AND completed_run.trace_id = pair.trace_id
       AND completed_run.completion_path = pair.completion_path
    LEFT JOIN event_groups AS completion
        ON completion.tenant_id = pair.tenant_id
       AND completion.trace_id = pair.trace_id
       AND completion.completion_path = pair.completion_path
    WHERE completed_run.row_count IS DISTINCT FROM 1::bigint
       OR completion.row_count IS DISTINCT FROM 1::bigint
       OR completed_run.final_decision IS DISTINCT FROM completion.final_decision;

    IF invalid_group_count > 0 THEN
        RAISE EXCEPTION
            'audit completion run/event parity validation failed (groups=%)',
            invalid_group_count
            USING ERRCODE = '23514';
    END IF;

    -- Replay is a bidirectional triple: replay run, completion event, and replay
    -- provenance must each exist exactly once and agree on source/final decision.
    WITH replay_runs AS (
        SELECT
            tenant_id,
            trace_id,
            count(*) AS row_count,
            min(payload #>> '{input,replay_of}') AS source_trace_id,
            min(payload ->> 'final_decision') AS replay_final_decision
        FROM audit_runs
        WHERE completion_path = '/verification/replay'
        GROUP BY tenant_id, trace_id
    ),
    replay_completions AS (
        SELECT
            tenant_id,
            trace_id,
            count(*) AS row_count,
            min(payload #>> '{metadata,final_decision}') AS replay_final_decision
        FROM audit_events
        WHERE payload ->> 'event_type' = 'verification_completed'
          AND payload ->> 'path' = '/verification/replay'
        GROUP BY tenant_id, trace_id
    ),
    replay_provenance AS (
        SELECT
            tenant_id,
            trace_id,
            count(*) AS row_count,
            min(payload #>> '{metadata,source_trace_id}') AS source_trace_id,
            min(payload #>> '{metadata,replay_final_decision}') AS replay_final_decision
        FROM audit_events
        WHERE payload ->> 'event_type' = 'verification_replay'
        GROUP BY tenant_id, trace_id
    ),
    replay_keys AS (
        SELECT tenant_id, trace_id FROM replay_runs
        UNION
        SELECT tenant_id, trace_id FROM replay_completions
        UNION
        SELECT tenant_id, trace_id FROM replay_provenance
    )
    SELECT count(*)
    INTO invalid_group_count
    FROM replay_keys AS replay_key
    LEFT JOIN replay_runs AS replayed_run
        ON replayed_run.tenant_id = replay_key.tenant_id
       AND replayed_run.trace_id = replay_key.trace_id
    LEFT JOIN replay_completions AS completion
        ON completion.tenant_id = replay_key.tenant_id
       AND completion.trace_id = replay_key.trace_id
    LEFT JOIN replay_provenance AS provenance
        ON provenance.tenant_id = replay_key.tenant_id
       AND provenance.trace_id = replay_key.trace_id
    WHERE replayed_run.row_count IS DISTINCT FROM 1::bigint
       OR completion.row_count IS DISTINCT FROM 1::bigint
       OR provenance.row_count IS DISTINCT FROM 1::bigint
       OR replayed_run.source_trace_id IS DISTINCT FROM provenance.source_trace_id
       OR replayed_run.replay_final_decision
            IS DISTINCT FROM completion.replay_final_decision
       OR replayed_run.replay_final_decision
            IS DISTINCT FROM provenance.replay_final_decision;

    IF invalid_group_count > 0 THEN
        RAISE EXCEPTION
            'audit replay run/completion/provenance parity validation failed (groups=%)',
            invalid_group_count
            USING ERRCODE = '23514';
    END IF;
END;
$audit_history_backfill$;

-- By the time 013 executes, the applier has backfilled every legacy NULL checksum
-- encountered in 000..012 and records all new versions with a SHA-256 checksum.
ALTER TABLE schema_migrations
    ALTER COLUMN checksum_sha256 TYPE text USING checksum_sha256::text,
    ALTER COLUMN checksum_sha256 DROP DEFAULT;

ALTER TABLE schema_migrations
    DROP CONSTRAINT IF EXISTS ck_schema_migrations_checksum_sha256;
ALTER TABLE schema_migrations
    ADD CONSTRAINT ck_schema_migrations_checksum_sha256
    CHECK ((
        checksum_sha256 IS NOT NULL
        AND checksum_sha256 ~ '^[0-9a-f]{64}$'
    ) IS TRUE) NOT VALID;
ALTER TABLE schema_migrations
    VALIDATE CONSTRAINT ck_schema_migrations_checksum_sha256;
ALTER TABLE schema_migrations
    ALTER COLUMN checksum_sha256 SET NOT NULL;

ALTER TABLE audit_runs
    DROP CONSTRAINT IF EXISTS ck_audit_runs_payload_envelope;
ALTER TABLE audit_runs
    ADD CONSTRAINT ck_audit_runs_payload_envelope
    CHECK ((
        jsonb_typeof(payload) = 'object'
        AND jsonb_typeof(payload -> 'tenant_id') = 'string'
        AND jsonb_typeof(payload -> 'trace_id') = 'string'
        AND jsonb_typeof(payload -> 'created_at') = 'string'
        AND tenant_id = payload ->> 'tenant_id'
        AND trace_id = payload ->> 'trace_id'
        AND created_at = (payload ->> 'created_at')::timestamptz
    ) IS TRUE) NOT VALID;
ALTER TABLE audit_runs
    VALIDATE CONSTRAINT ck_audit_runs_payload_envelope;

ALTER TABLE audit_runs
    DROP CONSTRAINT IF EXISTS ck_audit_runs_completion_contract;
ALTER TABLE audit_runs
    ADD CONSTRAINT ck_audit_runs_completion_contract
    CHECK ((
        completion_path IS NULL
        OR (
            tenant_id = btrim(tenant_id)
            AND tenant_id <> ''
            AND trace_id ~ '^tr_[A-Za-z0-9_-]{8,80}$'
            AND completion_path IN (
                '/verification/run',
                '/v2/verification/run',
                '/verification/replay'
            )
            AND jsonb_typeof(payload -> 'final_decision') = 'string'
            AND payload ->> 'final_decision' IN (
                'allow',
                'repaired',
                'abstained',
                'blocked',
                'require_human_review'
            )
            AND (
                completion_path <> '/verification/replay'
                OR (
                    jsonb_typeof(payload #> '{input,replay_of}') = 'string'
                    AND (payload #>> '{input,replay_of}')
                        ~ '^tr_[A-Za-z0-9_-]{8,80}$'
                )
            )
        )
    ) IS TRUE) NOT VALID;
ALTER TABLE audit_runs
    VALIDATE CONSTRAINT ck_audit_runs_completion_contract;

ALTER TABLE audit_events
    DROP CONSTRAINT IF EXISTS ck_audit_events_payload_envelope;
ALTER TABLE audit_events
    ADD CONSTRAINT ck_audit_events_payload_envelope
    CHECK ((
        jsonb_typeof(payload) = 'object'
        AND jsonb_typeof(payload -> 'tenant_id') = 'string'
        AND jsonb_typeof(payload -> 'trace_id') = 'string'
        AND jsonb_typeof(payload -> 'event_id') = 'string'
        AND jsonb_typeof(payload -> 'event_type') = 'string'
        AND jsonb_typeof(payload -> 'method') = 'string'
        AND jsonb_typeof(payload -> 'path') = 'string'
        AND jsonb_typeof(payload -> 'status_code') = 'number'
        AND jsonb_typeof(payload -> 'outcome') = 'string'
        AND jsonb_typeof(payload -> 'created_at') = 'string'
        AND tenant_id = payload ->> 'tenant_id'
        AND trace_id = payload ->> 'trace_id'
        AND event_id = payload ->> 'event_id'
        AND created_at = (payload ->> 'created_at')::timestamptz
        AND event_id ~ '^evt_[A-Za-z0-9_-]+$'
    ) IS TRUE) NOT VALID;
ALTER TABLE audit_events
    VALIDATE CONSTRAINT ck_audit_events_payload_envelope;

ALTER TABLE audit_events
    DROP CONSTRAINT IF EXISTS ck_audit_events_verification_completed;
ALTER TABLE audit_events
    ADD CONSTRAINT ck_audit_events_verification_completed
    CHECK ((
        CASE
            WHEN payload ->> 'event_type' = 'verification_completed' THEN
                tenant_id = btrim(tenant_id)
                AND tenant_id <> ''
                AND trace_id ~ '^tr_[A-Za-z0-9_-]{8,80}$'
                AND payload @> '{"method":"POST","status_code":200,"outcome":"success"}'::jsonb
                AND payload ->> 'path' IN (
                    '/verification/run',
                    '/v2/verification/run',
                    '/verification/replay'
                )
                AND jsonb_typeof(payload #> '{metadata,final_decision}') = 'string'
                AND payload #>> '{metadata,final_decision}' IN (
                    'allow',
                    'repaired',
                    'abstained',
                    'blocked',
                    'require_human_review'
                )
                AND payload -> 'metadata' = jsonb_build_object(
                    'final_decision', payload #>> '{metadata,final_decision}'
                )
            ELSE TRUE
        END
    ) IS TRUE) NOT VALID;
ALTER TABLE audit_events
    VALIDATE CONSTRAINT ck_audit_events_verification_completed;

ALTER TABLE audit_events
    DROP CONSTRAINT IF EXISTS ck_audit_events_verification_replay;
ALTER TABLE audit_events
    ADD CONSTRAINT ck_audit_events_verification_replay
    CHECK ((
        CASE
            WHEN payload ->> 'event_type' = 'verification_replay' THEN
                tenant_id = btrim(tenant_id)
                AND tenant_id <> ''
                AND trace_id ~ '^tr_[A-Za-z0-9_-]{8,80}$'
                AND payload @> '{"method":"POST","path":"/verification/replay","status_code":200,"outcome":"success"}'::jsonb
                AND jsonb_typeof(payload #> '{metadata,source_trace_id}') = 'string'
                AND (payload #>> '{metadata,source_trace_id}')
                    ~ '^tr_[A-Za-z0-9_-]{8,80}$'
                AND jsonb_typeof(payload #> '{metadata,source_final_decision}') = 'string'
                AND payload #>> '{metadata,source_final_decision}' IN (
                    'allow',
                    'repaired',
                    'abstained',
                    'blocked',
                    'require_human_review'
                )
                AND jsonb_typeof(payload #> '{metadata,replay_final_decision}') = 'string'
                AND payload #>> '{metadata,replay_final_decision}' IN (
                    'allow',
                    'repaired',
                    'abstained',
                    'blocked',
                    'require_human_review'
                )
                AND jsonb_typeof(payload #> '{metadata,decision_changed}') = 'boolean'
                AND payload #> '{metadata,decision_changed}' =
                    CASE
                        WHEN (payload #>> '{metadata,source_final_decision}')
                             <> (payload #>> '{metadata,replay_final_decision}')
                        THEN 'true'::jsonb
                        ELSE 'false'::jsonb
                    END
                AND payload -> 'metadata' = jsonb_build_object(
                    'source_trace_id', payload #>> '{metadata,source_trace_id}',
                    'source_final_decision', payload #>> '{metadata,source_final_decision}',
                    'replay_final_decision', payload #>> '{metadata,replay_final_decision}',
                    'decision_changed', payload #> '{metadata,decision_changed}'
                )
            ELSE TRUE
        END
    ) IS TRUE) NOT VALID;
ALTER TABLE audit_events
    VALIDATE CONSTRAINT ck_audit_events_verification_replay;

-- DROP/CREATE, instead of CREATE IF NOT EXISTS, makes a raw transactional rerun
-- repair a same-named but semantically drifted index definition.
-- The four 003 prefix indexes are superseded by the ordered/tiebroken definitions
-- below; retaining both would duplicate write and vacuum work.
DROP INDEX IF EXISTS ix_audit_runs_tenant_created;
DROP INDEX IF EXISTS ix_audit_runs_tenant_trace;
DROP INDEX IF EXISTS ix_audit_events_tenant_created;
DROP INDEX IF EXISTS ix_audit_events_tenant_trace;

DROP INDEX IF EXISTS ux_audit_runs_tenant_trace_completion_path;
CREATE UNIQUE INDEX ux_audit_runs_tenant_trace_completion_path
    ON audit_runs (tenant_id, trace_id, completion_path)
    WHERE completion_path IS NOT NULL;

DROP INDEX IF EXISTS ux_audit_events_tenant_trace_completion_path;
CREATE UNIQUE INDEX ux_audit_events_tenant_trace_completion_path
    ON audit_events (tenant_id, trace_id, (payload ->> 'path'))
    WHERE payload ->> 'event_type' = 'verification_completed';

DROP INDEX IF EXISTS ux_audit_events_tenant_trace_replay_path;
CREATE UNIQUE INDEX ux_audit_events_tenant_trace_replay_path
    ON audit_events (tenant_id, trace_id, (payload ->> 'path'))
    WHERE payload ->> 'event_type' = 'verification_replay';

DROP INDEX IF EXISTS ux_audit_events_tenant_event_id;
CREATE UNIQUE INDEX ux_audit_events_tenant_event_id
    ON audit_events (tenant_id, event_id);

DROP INDEX IF EXISTS ix_audit_runs_created_id;
CREATE INDEX ix_audit_runs_created_id
    ON audit_runs (created_at DESC, id DESC);

DROP INDEX IF EXISTS ix_audit_runs_trace_created_id;
CREATE INDEX ix_audit_runs_trace_created_id
    ON audit_runs (trace_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS ix_audit_runs_tenant_created_id;
CREATE INDEX ix_audit_runs_tenant_created_id
    ON audit_runs (tenant_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS ix_audit_runs_tenant_trace_created_id;
CREATE INDEX ix_audit_runs_tenant_trace_created_id
    ON audit_runs (tenant_id, trace_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS ix_audit_events_created_id;
CREATE INDEX ix_audit_events_created_id
    ON audit_events (created_at DESC, id DESC);

DROP INDEX IF EXISTS ix_audit_events_trace_created_id;
CREATE INDEX ix_audit_events_trace_created_id
    ON audit_events (trace_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS ix_audit_events_tenant_created_id;
CREATE INDEX ix_audit_events_tenant_created_id
    ON audit_events (tenant_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS ix_audit_events_tenant_trace_created_id;
CREATE INDEX ix_audit_events_tenant_trace_created_id
    ON audit_events (tenant_id, trace_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS ix_audit_events_tenant_type_created_event;
CREATE INDEX ix_audit_events_tenant_type_created_event
    ON audit_events (
        tenant_id,
        (payload ->> 'event_type'),
        created_at DESC,
        event_id DESC
    );

DROP INDEX IF EXISTS ix_audit_events_tenant_type_trace_created_event;
CREATE INDEX ix_audit_events_tenant_type_trace_created_event
    ON audit_events (
        tenant_id,
        (payload ->> 'event_type'),
        trace_id,
        created_at DESC,
        event_id DESC
    );
