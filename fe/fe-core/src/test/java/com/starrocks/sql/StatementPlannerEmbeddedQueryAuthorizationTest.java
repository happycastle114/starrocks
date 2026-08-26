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

import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.analyzer.PlannerMetaLocker;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.sql.plan.PlanTestBase;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class StatementPlannerEmbeddedQueryAuthorizationTest extends PlanTestBase {
    private static final String FILES_RELATION =
            "FILES('path' = 'file:///__managed_embedded_missing__', 'format' = 'parquet')";

    @Test
    public void testManagedEmbeddedFilesIsDeniedBeforeAnalyzerForEverySupportedWrapper() {
        Map<String, String> statements = new LinkedHashMap<>();
        statements.put("query", "SELECT * FROM " + FILES_RELATION);
        statements.put("insert", "INSERT INTO t0 SELECT * FROM " + FILES_RELATION);
        statements.put("insert target",
                "INSERT INTO FILES('path' = 'file:///__managed_target__', 'format' = 'parquet') SELECT 1");
        statements.put("pipe", "CREATE PIPE embedded_pipe AS INSERT INTO t0 SELECT * FROM " + FILES_RELATION);
        statements.put("submit insert",
                "SUBMIT TASK embedded_insert AS INSERT INTO t0 SELECT * FROM " + FILES_RELATION);
        statements.put("submit ctas",
                "SUBMIT TASK embedded_ctas AS CREATE TABLE embedded_task_table AS SELECT * FROM " + FILES_RELATION);
        statements.put("ctas", "CREATE TABLE embedded_ctas_table AS SELECT * FROM " + FILES_RELATION);
        statements.put("temporary ctas",
                "CREATE TEMPORARY TABLE embedded_temp_table AS SELECT * FROM " + FILES_RELATION);
        statements.put("create view", "CREATE VIEW embedded_view AS SELECT * FROM " + FILES_RELATION);
        statements.put("replace view",
                "CREATE OR REPLACE VIEW embedded_view AS SELECT * FROM " + FILES_RELATION);
        statements.put("alter view", "ALTER VIEW embedded_view AS SELECT * FROM " + FILES_RELATION);
        statements.put("async materialized view",
                "CREATE MATERIALIZED VIEW embedded_async_mv DISTRIBUTED BY HASH(c1) REFRESH MANUAL " +
                        "AS SELECT * FROM " + FILES_RELATION);
        statements.put("legacy materialized view",
                "CREATE MATERIALIZED VIEW embedded_sync_mv AS SELECT * FROM " + FILES_RELATION);
        Set<String> storedDefinitionCases = Set.of(
                "create view", "replace view", "alter view",
                "async materialized view", "legacy materialized view");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            for (Map.Entry<String, String> testCase : statements.entrySet()) {
                StatementBase statement = parse(testCase.getValue());
                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> StatementPlanner.plan(statement, connectContext), testCase.getKey());
                String denialScope = storedDefinitionCases.contains(testCase.getKey())
                        ? "stored definition" : "query";
                Assertions.assertTrue(exception.getMessage().contains("Ranger-managed " + denialScope + ": FILES"),
                        testCase.getKey() + ": " + exception.getMessage());
            }
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testManagedStoredMetadataDefinitionIsDeniedBeforeAnalyzer() {
        Map<String, String> statements = new LinkedHashMap<>();
        statements.put("create view",
                "CREATE VIEW stored_info_view AS SELECT * FROM information_schema.tables");
        statements.put("replace view",
                "CREATE OR REPLACE VIEW stored_info_view AS SELECT * FROM information_schema.columns");
        statements.put("alter view",
                "ALTER VIEW stored_info_view AS SELECT * FROM information_schema.tables");
        statements.put("async materialized view",
                "CREATE MATERIALIZED VIEW stored_info_async_mv DISTRIBUTED BY HASH(TABLE_NAME) REFRESH MANUAL " +
                        "AS SELECT TABLE_NAME FROM information_schema.tables");
        statements.put("legacy materialized view",
                "CREATE MATERIALIZED VIEW stored_info_sync_mv AS " +
                        "SELECT TABLE_NAME FROM information_schema.tables");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            for (Map.Entry<String, String> testCase : statements.entrySet()) {
                StatementBase statement = parse(testCase.getValue());
                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> StatementPlanner.plan(statement, connectContext), testCase.getKey());
                Assertions.assertTrue(
                        exception.getMessage().contains("Ranger-managed stored definition: INFORMATION_SCHEMA"),
                        testCase.getKey() + ": " + exception.getMessage());
            }
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testOrdinaryEmbeddedFilesKeepsExistingAnalyzerPath() {
        StatementBase ctas = parse("CREATE TABLE ordinary_ctas AS SELECT * FROM " + FILES_RELATION);
        StatementBase insertTarget = parse(
                "INSERT INTO FILES('path' = 'file:///__ordinary_target__', 'format' = 'parquet') SELECT 1");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(ctas, connectContext));
            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(insertTarget, connectContext));
            Assertions.assertEquals(2, analyzerCalls.get());
        }
    }

    @Test
    public void testBypassInsertIntoFilesTargetKeepsExistingAnalyzerPath() {
        StatementBase insertTarget = parse(
                "INSERT INTO FILES('path' = 'file:///__bypass_target__', 'format' = 'parquet') SELECT 1");
        AtomicInteger analyzerCalls = mockAnalyzer();
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(insertTarget, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(
                    () -> Authorizer.checkRangerManagedFileTableFunctionTargetBeforeAnalysis(connectContext),
                    Mockito.never());
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
        }
    }

    private static StatementBase parse(String sql) {
        return SqlParser.parse(sql, connectContext.getSessionVariable()).get(0);
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

    private static class StopPlanningException extends RuntimeException {
    }
}
