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

import com.starrocks.analysis.TableName;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.common.ErrorCode;
import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.analyzer.PlannerMetaLocker;
import com.starrocks.sql.analyzer.PreAnalyzerAuthorization;
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
import java.util.concurrent.atomic.AtomicInteger;

public class StatementPlannerRangerManagedDataMovementAuthorizationTest extends PlanTestBase {
    @Test
    public void testManagedDataMovementIsDeniedWithPermissivePrivileges() throws Exception {
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer = permissiveAuthorizer(true)) {
            for (Map.Entry<String, String> testCase : dataMovementStatements().entrySet()) {
                StatementBase statement = parse(testCase.getKey());
                ErrorReportException exception = Assertions.assertThrows(
                        ErrorReportException.class,
                        () -> StatementPlanner.plan(statement, connectContext),
                        testCase.getKey());
                Assertions.assertEquals(ErrorCode.ERR_ACCESS_DENIED_FOR_EXTERNAL_ACCESS_CONTROLLER,
                        exception.getErrorCode());
                Assertions.assertTrue(exception.getMessage().contains(
                                "Ranger-managed statement: " + testCase.getValue()),
                        exception.getMessage());
            }

            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                            Mockito.same(connectContext), Mockito.anyString(), Mockito.anyString(),
                            Mockito.any(PrivilegeType.class)),
                    Mockito.never());
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                            Mockito.same(connectContext), Mockito.any(TableName.class),
                            Mockito.any(PrivilegeType.class)),
                    Mockito.never());
            authorizer.verify(() -> Authorizer.checkTableAction(
                            Mockito.same(connectContext), Mockito.any(TableName.class),
                            Mockito.any(PrivilegeType.class)),
                    Mockito.never());
            authorizer.verify(() -> Authorizer.checkMaterializedViewAction(
                            Mockito.same(connectContext), Mockito.any(TableName.class),
                            Mockito.any(PrivilegeType.class)),
                    Mockito.never());
        }
    }

    @Test
    public void testOrdinaryDataMovementKeepsExistingAnalyzerPath() throws Exception {
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> ignored = permissiveAuthorizer(false)) {
            for (String sql : dataMovementStatements().keySet()) {
                StatementBase statement = parse(sql);
                Assertions.assertThrows(StopPlanningException.class,
                        () -> StatementPlanner.plan(statement, connectContext), sql);
            }
        }

        Assertions.assertEquals(dataMovementStatements().size(), analyzerCalls.get());
    }

    @Test
    public void testManagedNonMaterializingAlterKeepsExistingAnalyzerPath() throws Exception {
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> ignored = permissiveAuthorizer(true)) {
            for (String sql : nonMaterializingAlterStatements()) {
                StatementBase statement = parse(sql);
                Assertions.assertThrows(StopPlanningException.class,
                        () -> StatementPlanner.plan(statement, connectContext), sql);
            }
        }

        Assertions.assertEquals(nonMaterializingAlterStatements().length, analyzerCalls.get());
    }

    @Test
    public void testDirectManagedPreauthorizationDeniesDataMovement() throws Exception {
        try (MockedStatic<Authorizer> ignored = permissiveAuthorizer(true)) {
            for (Map.Entry<String, String> testCase : dataMovementStatements().entrySet()) {
                StatementBase statement = parse(testCase.getKey());
                ErrorReportException exception = Assertions.assertThrows(
                        ErrorReportException.class,
                        () -> PreAnalyzerAuthorization.checkRangerManagedQuery(statement, connectContext),
                        testCase.getKey());
                Assertions.assertEquals(ErrorCode.ERR_ACCESS_DENIED_FOR_EXTERNAL_ACCESS_CONTROLLER,
                        exception.getErrorCode());
                Assertions.assertTrue(exception.getMessage().contains(
                                "Ranger-managed statement: " + testCase.getValue()),
                        exception.getMessage());
            }
        }
    }

    @Test
    public void testBypassDataMovementKeepsExistingAnalyzerPath() {
        AtomicInteger analyzerCalls = mockAnalyzer();
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            for (String sql : dataMovementStatements().keySet()) {
                StatementBase statement = parse(sql);
                Assertions.assertThrows(StopPlanningException.class,
                        () -> StatementPlanner.plan(statement, connectContext), sql);
            }
            authorizer.verify(
                    () -> Authorizer.isRangerManagedContext(connectContext), Mockito.never());
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
        }

        Assertions.assertEquals(dataMovementStatements().size(), analyzerCalls.get());
    }

    private static MockedStatic<Authorizer> permissiveAuthorizer(boolean rangerManaged) throws Exception {
        MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS);
        authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(rangerManaged);
        authorizer.when(() -> Authorizer.checkDbAction(
                        Mockito.same(connectContext), Mockito.anyString(), Mockito.anyString(),
                        Mockito.any(PrivilegeType.class)))
                .thenAnswer(invocation -> null);
        authorizer.when(() -> Authorizer.checkTableActionByName(
                        Mockito.same(connectContext), Mockito.any(TableName.class),
                        Mockito.any(PrivilegeType.class)))
                .thenAnswer(invocation -> null);
        authorizer.when(() -> Authorizer.checkTableAction(
                        Mockito.same(connectContext), Mockito.any(TableName.class),
                        Mockito.any(PrivilegeType.class)))
                .thenAnswer(invocation -> null);
        authorizer.when(() -> Authorizer.checkMaterializedViewAction(
                        Mockito.same(connectContext), Mockito.any(TableName.class),
                        Mockito.any(PrivilegeType.class)))
                .thenAnswer(invocation -> null);
        return authorizer;
    }

    private static Map<String, String> dataMovementStatements() {
        Map<String, String> statements = new LinkedHashMap<>();
        statements.put("EXPORT TABLE t0 TO 'hdfs://host/export/' WITH ASYNC MODE", "EXPORT");
        statements.put("EXPORT TABLE t0 TO 'hdfs://host/export/' WITH SYNC MODE", "EXPORT");
        statements.put(
                "CREATE MATERIALIZED VIEW managed_async_mv DISTRIBUTED BY HASH(v1) " +
                        "REFRESH MANUAL AS SELECT v1 FROM t0",
                "CREATE MATERIALIZED VIEW");
        statements.put(
                "CREATE MATERIALIZED VIEW managed_sync_mv AS SELECT v1 FROM t0",
                "CREATE MATERIALIZED VIEW");
        statements.put("REFRESH MATERIALIZED VIEW managed_async_mv", "REFRESH MATERIALIZED VIEW");
        statements.put(
                "REFRESH MATERIALIZED VIEW managed_async_mv FORCE WITH SYNC MODE WITH PRIORITY 1",
                "REFRESH MATERIALIZED VIEW");
        statements.put(
                "ALTER MATERIALIZED VIEW managed_async_mv REFRESH ASYNC",
                "ALTER MATERIALIZED VIEW REFRESH ASYNC");
        statements.put(
                "ALTER MATERIALIZED VIEW managed_async_mv " +
                        "REFRESH ASYNC EVERY(INTERVAL 1 DAY)",
                "ALTER MATERIALIZED VIEW REFRESH ASYNC");
        statements.put(
                "ALTER MATERIALIZED VIEW managed_async_mv REFRESH INCREMENTAL",
                "ALTER MATERIALIZED VIEW REFRESH INCREMENTAL");
        statements.put(
                "ALTER MATERIALIZED VIEW managed_async_mv ACTIVE",
                "ALTER MATERIALIZED VIEW ACTIVE");
        statements.put(
                "ALTER TABLE t0 ADD ROLLUP managed_rollup (v1, v2)",
                "ALTER TABLE ADD ROLLUP");
        statements.put(
                "ALTER TABLE t0 ADD ROLLUP managed_rollup_1 (v1), " +
                        "managed_rollup_2 (v1, v2) FROM managed_rollup_1",
                "ALTER TABLE ADD ROLLUP");
        return statements;
    }

    private static String[] nonMaterializingAlterStatements() {
        return new String[] {
                "ALTER MATERIALIZED VIEW managed_async_mv REFRESH MANUAL",
                "ALTER MATERIALIZED VIEW managed_async_mv INACTIVE",
                "ALTER TABLE t0 DROP ROLLUP managed_rollup"
        };
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
