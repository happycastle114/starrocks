// Copyright 2021-present StarRocks, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.starrocks.sql;

import com.starrocks.analysis.BinaryPredicate;
import com.starrocks.analysis.BinaryType;
import com.starrocks.analysis.IntLiteral;
import com.starrocks.analysis.SlotRef;
import com.starrocks.analysis.TableName;
import com.starrocks.authorization.SecurityPolicyRewriteRule;
import com.starrocks.catalog.Column;
import com.starrocks.catalog.Database;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.catalog.MysqlTable;
import com.starrocks.catalog.Table;
import com.starrocks.catalog.Type;
import com.starrocks.catalog.View;
import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.sql.analyzer.Analyzer;
import com.starrocks.sql.analyzer.AnalyzerUtils;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.analyzer.PlannerMetaLocker;
import com.starrocks.sql.analyzer.PreAnalyzerAuthorization;
import com.starrocks.sql.ast.QueryStatement;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.ast.TableRelation;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.sql.plan.PlanTestBase;
import com.starrocks.sql.spm.SPMPlanner;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class StatementPlannerRangerManagedQueryAuthorizationTest extends PlanTestBase {
    @Test
    public void testManagedFilesIsDeniedBeforeAnalyzer() {
        QueryStatement statement = parse(
                "SELECT * FROM FILES('path' = 'file:///__ranger_managed_missing__')");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertTrue(exception.getMessage().contains("Ranger-managed query: FILES"),
                    exception.getMessage());
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testManagedDirectQueryUsesFullForbiddenRegistry() {
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("SELECT HOST_NAME()", "HOST_NAME");
        cases.put("SELECT NATIVE_QUERY()", "NATIVE_QUERY");
        cases.put("SELECT SLEEP(3600)", "SLEEP");
        cases.put("SELECT INSPECT_FUTURE()", "INSPECT_FUTURE");
        cases.put("SELECT * FROM information_schema.processlist", "INFORMATION_SCHEMA");
        cases.put("SELECT value FROM db.tbl [_SYNC_MV_]", "_SYNC_MV_");
        cases.put("SELECT * FROM iceberg.db.`events$files`", "events$files");
        cases.put("SELECT /*+ SET_VAR(query_timeout = 1) */ 1", "SET_VAR");
        cases.put("SELECT 1 INTO OUTFILE 'file:///__managed_outfile__' FORMAT AS CSV", "OUTFILE");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);
            for (Map.Entry<String, String> testCase : cases.entrySet()) {
                QueryStatement statement = parse(testCase.getKey());
                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> StatementPlanner.plan(statement, connectContext));
                Assertions.assertTrue(exception.getMessage().contains(testCase.getValue()), exception.getMessage());
            }
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testOrdinaryQueryContinuesToAnalyzer() {
        QueryStatement statement = parse(
                "SELECT * FROM FILES('path' = 'file:///__ordinary_missing__')");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
        }
    }

    @Test
    public void testOrdinaryOutfileContinuesToAnalyzer() {
        QueryStatement statement = parse(
                "SELECT 1 INTO OUTFILE 'file:///__ordinary_outfile__' FORMAT AS CSV");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
        }
    }

    @Test
    public void testManagedSafeQueryContinuesToAnalyzer() {
        QueryStatement statement = parse("SELECT ABS(-1), CURRENT_USER()");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
        }
    }

    @Test
    public void testManagedQuerySkipsSpmReplacement() {
        QueryStatement statement = parse("SELECT ABS(-1)");
        AtomicInteger spmCalls = mockSpmPlanner();
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, spmCalls.get());
            Assertions.assertEquals(1, analyzerCalls.get());
        }
    }

    @Test
    public void testOrdinaryQueryKeepsSpmReplacement() {
        QueryStatement statement = parse("SELECT ABS(-1)");
        AtomicInteger spmCalls = mockSpmPlanner();
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, spmCalls.get());
            Assertions.assertEquals(1, analyzerCalls.get());
        }
    }

    @Test
    public void testManagedGatewayMetadataQueryContinuesToAnalyzer() {
        List<QueryStatement> statements = List.of(
                parse("SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.tables AS t " +
                        "WHERE t.TABLE_SCHEMA = 'test'"),
                parse("SELECT TABLE_NAME, COLUMN_NAME FROM default_catalog.`InFoRmAtIoN_sChEmA`.`CoLuMnS` AS c"));
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            for (QueryStatement statement : statements) {
                Assertions.assertThrows(StopPlanningException.class,
                        () -> StatementPlanner.plan(statement, connectContext));
            }
            Assertions.assertEquals(statements.size(), analyzerCalls.get());
        }
    }

    @Test
    public void testManagedMetadataAllowlistRejectsForeignAndUnknownRelations() {
        List<QueryStatement> statements = List.of(
                parse("SELECT * FROM attacker_catalog.information_schema.tables"),
                parse("SELECT * FROM information_schema.unknown_metadata"));
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);
            for (QueryStatement statement : statements) {
                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> StatementPlanner.plan(statement, connectContext));
                Assertions.assertTrue(exception.getMessage().contains("INFORMATION_SCHEMA"), exception.getMessage());
            }
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testManagedMetadataAllowlistUsesCurrentNamespace() {
        String originalCatalog = connectContext.getCurrentCatalog();
        String originalDatabase = connectContext.getDatabase();
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            connectContext.setCurrentCatalog("attacker_catalog");
            ErrorReportException foreignCatalog = Assertions.assertThrows(ErrorReportException.class,
                    () -> StatementPlanner.plan(parse("SELECT * FROM information_schema.tables"), connectContext));
            Assertions.assertTrue(foreignCatalog.getMessage().contains("INFORMATION_SCHEMA"),
                    foreignCatalog.getMessage());

            connectContext.setCurrentCatalog(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME);
            connectContext.setDatabase("information_schema");
            ErrorReportException currentDatabase = Assertions.assertThrows(ErrorReportException.class,
                    () -> StatementPlanner.plan(parse("SELECT * FROM processlist"), connectContext));
            Assertions.assertTrue(currentDatabase.getMessage().contains("INFORMATION_SCHEMA"),
                    currentDatabase.getMessage());
            Assertions.assertEquals(0, analyzerCalls.get());
        } finally {
            connectContext.setCurrentCatalog(originalCatalog);
            connectContext.setDatabase(originalDatabase);
        }
    }

    @Test
    public void testManagedStoredViewFilesIsDeniedBeforeDefinitionAnalysis() {
        Database database = GlobalStateMgr.getCurrentState().getLocalMetastore().getDb("test");
        View view = new View(987654321L, "managed_stored_files_view",
                List.of(new Column("value", Type.VARCHAR)));
        view.setInlineViewDefWithSqlMode(
                "SELECT * FROM FILES('path' = 'file:///__stored_view_missing__', 'format' = 'parquet')", 0);
        Assertions.assertTrue(database.registerTableUnlocked(view));

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                    () -> StatementPlanner.plan(parse("SELECT * FROM managed_stored_files_view"), connectContext));
            Assertions.assertTrue(exception.getMessage().contains("Ranger-managed stored definition: FILES"),
                    exception.getMessage());
        } finally {
            database.unRegisterTableUnlocked(view);
        }
    }

    @Test
    public void testManagedAsyncMaterializedViewIsDeniedBeforeRowPolicyAnalysis() throws Exception {
        String materializedView = "managed_aggregate_async_mv";
        starRocksAssert.withMaterializedView(
                "CREATE MATERIALIZED VIEW test." + materializedView + " " +
                        "DISTRIBUTED BY RANDOM BUCKETS 1 " +
                        "REFRESH DEFERRED MANUAL " +
                        "PROPERTIES ('replication_num' = '1') " +
                        "AS SELECT COUNT(*) AS tenant_count FROM test.t0");
        AtomicInteger rowPolicyCalls = new AtomicInteger();

        try {
            QueryStatement statement = parse("SELECT tenant_count FROM test." + materializedView);
            SecurityPolicyRewriteRule.markRelationsForRewrite(statement);
            try (MockedStatic<Authorizer> authorizer =
                         Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
                authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);
                authorizer.when(() -> Authorizer.getRowAccessPolicy(
                                Mockito.same(connectContext), Mockito.any(TableName.class)))
                        .thenAnswer(invocation -> {
                            rowPolicyCalls.incrementAndGet();
                            return new SlotRef(null, "channel_id");
                        });

                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> StatementPlanner.plan(statement, connectContext));
                Assertions.assertTrue(exception.getMessage().contains(
                        "Ranger-managed materialized view: test." + materializedView), exception.getMessage());
                Assertions.assertEquals(0, rowPolicyCalls.get());
            }
        } finally {
            starRocksAssert.dropMaterializedView("test." + materializedView);
        }
    }

    @Test
    public void testManagedResolvedExternalTableAndStoredViewAreDeniedAfterAnalyzer() throws Exception {
        Database database = GlobalStateMgr.getCurrentState().getLocalMetastore().getDb("test");
        MysqlTable externalTable = new MysqlTable(987654322L, "managed_external_mysql",
                List.of(new Column("channel_id", Type.BIGINT), new Column("value", Type.VARCHAR)),
                Map.of(
                        "host", "127.0.0.1",
                        "port", "18080",
                        "user", "recorder",
                        "password", "",
                        "database", "test",
                        "table", "managed_external_mysql_remote"));
        View externalView = new View(987654323L, "managed_external_mysql_view",
                List.of(new Column("channel_id", Type.BIGINT), new Column("value", Type.VARCHAR)));
        externalView.setInlineViewDefWithSqlMode(
                "SELECT channel_id, value FROM test.managed_external_mysql", 0);
        Assertions.assertTrue(database.registerTableUnlocked(externalTable));
        Assertions.assertTrue(database.registerTableUnlocked(externalView));

        QueryStatement directStatement = parse("SELECT * FROM test.managed_external_mysql");
        QueryStatement viewStatement = parse("SELECT * FROM test.managed_external_mysql_view");
        List<QueryStatement> managedStatements = List.of(directStatement, viewStatement);
        managedStatements.forEach(SecurityPolicyRewriteRule::markRelationsForRewrite);
        AtomicInteger rowPolicyCalls = new AtomicInteger();
        AtomicInteger authorizationCalls = new AtomicInteger();
        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);
            authorizer.when(() -> Authorizer.getColumnMaskingPolicy(
                            Mockito.same(connectContext), Mockito.any(TableName.class), Mockito.anyList()))
                    .thenReturn(Map.of());
            authorizer.when(() -> Authorizer.getRowAccessPolicy(
                            Mockito.same(connectContext), Mockito.any(TableName.class)))
                    .thenAnswer(invocation -> {
                        rowPolicyCalls.incrementAndGet();
                        return new BinaryPredicate(BinaryType.EQ,
                                new SlotRef(null, "channel_id"), new IntLiteral(1));
                    });
            authorizer.when(() -> Authorizer.check(
                            Mockito.any(StatementBase.class), Mockito.same(connectContext)))
                    .thenAnswer(invocation -> {
                        authorizationCalls.incrementAndGet();
                        return null;
                    });

            for (QueryStatement statement : managedStatements) {
                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> StatementPlanner.plan(statement, connectContext));
                Assertions.assertTrue(exception.getMessage().contains(
                        "Ranger-managed query: test.managed_external_mysql (MYSQL)"), exception.getMessage());
                Assertions.assertTrue(AnalyzerUtils.collectTableRelations(statement).stream()
                        .map(TableRelation::getTable)
                        .anyMatch(table -> table != null
                                && table.getType() == Table.TableType.MYSQL
                                && "managed_external_mysql".equals(table.getName())));
            }
            Assertions.assertTrue(rowPolicyCalls.get() >= managedStatements.size());
            Assertions.assertEquals(0, authorizationCalls.get());

            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);
            Assertions.assertDoesNotThrow(() -> PreAnalyzerAuthorization.authorizeAfter(
                    directStatement, connectContext, PreAnalyzerAuthorization.Result.FULL_STATEMENT));

            connectContext.setBypassAuthorizerCheck(true);
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);
            Assertions.assertDoesNotThrow(() -> PreAnalyzerAuthorization.authorizeAfter(
                    directStatement, connectContext, PreAnalyzerAuthorization.Result.FULL_STATEMENT));
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
            database.unRegisterTableUnlocked(externalView);
            database.unRegisterTableUnlocked(externalTable);
        }
    }

    @Test
    public void testManagedResolvedNativeViewAndRequiredSchemaTablePassExternalGuard() {
        Database database = GlobalStateMgr.getCurrentState().getLocalMetastore().getDb("test");
        View nativeView = new View(987654324L, "managed_native_view",
                List.of(new Column("v1", Type.BIGINT)));
        nativeView.setInlineViewDefWithSqlMode("SELECT v1 FROM test.t0", 0);
        Assertions.assertTrue(database.registerTableUnlocked(nativeView));

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);
            List<QueryStatement> statements = List.of(
                    parse("SELECT * FROM test.managed_native_view"),
                    parse("SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.tables"));

            for (QueryStatement statement : statements) {
                Analyzer.analyze(statement, connectContext);
                Assertions.assertDoesNotThrow(() -> PreAnalyzerAuthorization.authorizeAfter(
                        statement, connectContext, PreAnalyzerAuthorization.Result.FULL_STATEMENT));
            }
        } finally {
            database.unRegisterTableUnlocked(nativeView);
        }
    }

    @Test
    public void testBypassContinuesWithoutManagedQueryAuthorization() {
        QueryStatement statement = parse(
                "SELECT * FROM FILES('path' = 'file:///__bypass_missing__')");
        AtomicInteger spmCalls = mockSpmPlanner();
        AtomicInteger analyzerCalls = mockAnalyzer();
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, spmCalls.get());
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkRangerManagedQueryBeforeAnalysis(statement, connectContext),
                    Mockito.never());
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
        }
    }

    private static QueryStatement parse(String sql) {
        return (QueryStatement) SqlParser.parse(sql, connectContext.getSessionVariable()).get(0);
    }

    private static AtomicInteger mockAnalyzer() {
        AtomicInteger calls = new AtomicInteger();
        new MockUp<StatementPlanner>() {
            @Mock
            public boolean analyzeStatement(StatementBase statement, ConnectContext context,
                                            PlannerMetaLocker locker) {
                calls.incrementAndGet();
                throw new StopPlanningException();
            }

            @Mock
            public void unLock(PlannerMetaLocker locker) {
            }
        };
        return calls;
    }

    private static AtomicInteger mockSpmPlanner() {
        AtomicInteger calls = new AtomicInteger();
        new MockUp<SPMPlanner>() {
            @Mock
            public StatementBase plan(StatementBase statement) {
                calls.incrementAndGet();
                return statement;
            }
        };
        return calls;
    }

    private static class StopPlanningException extends RuntimeException {
    }
}
