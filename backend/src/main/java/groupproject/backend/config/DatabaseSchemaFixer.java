package groupproject.backend.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * Runs once on startup to drop any stale unique constraints that were generated
 * by the old @OneToOne mapping on LoanDecision.loan_id.
 * ddl-auto=update never drops constraints, so we must do it manually.
 */
@Slf4j
@Component
public class DatabaseSchemaFixer implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    public DatabaseSchemaFixer(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(ApplicationArguments args) {
        dropUniqueConstraintsOnLoanDecisions();
    }

    private void dropUniqueConstraintsOnLoanDecisions() {
        try {
            // Drop any UNIQUE constraints on loan_decisions.loan_id
            String constraintSql = """
                DO $$
                DECLARE
                    rec RECORD;
                BEGIN
                    FOR rec IN
                        SELECT kcu.constraint_name
                        FROM information_schema.key_column_usage kcu
                        JOIN information_schema.table_constraints tc
                          ON tc.constraint_name = kcu.constraint_name
                         AND tc.table_name = kcu.table_name
                        WHERE kcu.table_name = 'loan_decisions'
                          AND kcu.column_name = 'loan_id'
                          AND tc.constraint_type = 'UNIQUE'
                    LOOP
                        EXECUTE 'ALTER TABLE loan_decisions DROP CONSTRAINT IF EXISTS "' || rec.constraint_name || '"';
                        RAISE NOTICE 'Dropped unique constraint: %', rec.constraint_name;
                    END LOOP;
                END
                $$;
                """;
            jdbcTemplate.execute(constraintSql);

            // Also drop any stale unique INDEXES on loan_decisions.loan_id
            // (ddl-auto=update creates indexes but never removes them)
            String indexSql = """
                DO $$
                DECLARE
                    rec RECORD;
                BEGIN
                    FOR rec IN
                        SELECT i.relname AS index_name
                        FROM pg_index ix
                        JOIN pg_class t  ON t.oid  = ix.indrelid
                        JOIN pg_class i  ON i.oid  = ix.indexrelid
                        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
                        WHERE t.relname = 'loan_decisions'
                          AND a.attname  = 'loan_id'
                          AND ix.indisunique = true
                          AND ix.indisprimary = false
                    LOOP
                        EXECUTE 'DROP INDEX IF EXISTS "' || rec.index_name || '"';
                        RAISE NOTICE 'Dropped unique index: %', rec.index_name;
                    END LOOP;
                END
                $$;
                """;
            jdbcTemplate.execute(indexSql);

            log.info("DatabaseSchemaFixer: loan_decisions.loan_id unique constraint/index check complete");
        } catch (Exception e) {
            log.warn("DatabaseSchemaFixer: could not check/drop unique constraint on loan_decisions: {}", e.getMessage());
        }
    }
}
