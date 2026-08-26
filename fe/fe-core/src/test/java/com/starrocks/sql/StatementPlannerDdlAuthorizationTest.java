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
import com.starrocks.catalog.InternalCatalog;
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

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class StatementPlannerDdlAuthorizationTest extends PlanTestBase {
    @Test
    public void testDeniedTableCreationWrappersDoNotReachAnalyzer() {
        List<StatementBase> statements = List.of(
                parse("CREATE TABLE denied_ctas AS SELECT 1"),
                parse("CREATE TEMPORARY TABLE denied_temp_ctas AS SELECT 1"),
                parse("SUBMIT TASK denied_task_ctas AS CREATE TABLE denied_task_table AS SELECT 1"));
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkDbAction(
                            connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                            "test", PrivilegeType.CREATE_TABLE))
                    .thenThrow(new SecurityException("CREATE_TABLE denied"));
            authorizer.clearInvocations();

            for (StatementBase statement : statements) {
                Assertions.assertThrows(SecurityException.class,
                        () -> StatementPlanner.plan(statement, connectContext));
            }
            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    "test", PrivilegeType.CREATE_TABLE), Mockito.times(statements.size()));
        }
    }

    @Test
    public void testDeniedTemporaryTableLikeSourceDoesNotReachAnalyzer() {
        StatementBase statement = parse(
                "CREATE TEMPORARY TABLE denied_temp LIKE missing_temp_source");
        AtomicInteger analyzerCalls = mockAnalyzer();
        TableName source = new TableName(
                InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, "test", "missing_temp_source");

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkSelectOnUnresolvedTableLikeObject(
                            connectContext, source))
                    .thenThrow(new SecurityException("SELECT denied"));
            authorizer.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkSelectOnUnresolvedTableLikeObject(
                    connectContext, source), Mockito.times(1));
        }
    }

    @Test
    public void testDeniedPlanAdvisorSourceDoesNotReachAnalyzer() {
        StatementBase statement = parse(
                "ALTER PLAN ADVISOR ADD SELECT * FROM db1.missing_advisor_source");
        AtomicInteger analyzerCalls = mockAnalyzer();
        TableName source = new TableName(
                InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                "db1", "missing_advisor_source");

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkSelectOnUnresolvedTableLikeObject(
                            connectContext, source))
                    .thenThrow(new SecurityException("SELECT denied"));
            authorizer.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkSelectOnUnresolvedTableLikeObject(
                    connectContext, source), Mockito.times(1));
        }
    }

    @Test
    public void testPlanAdvisorCteScopeAuthorizesOnlyPhysicalSources() {
        StatementBase statement = parse(
                "ALTER PLAN ADVISOR ADD WITH source_cte AS "
                        + "(SELECT * FROM physical_source), physical_source AS (SELECT 1) "
                        + "SELECT * FROM source_cte");
        AtomicInteger analyzerCalls = mockAnalyzer();
        TableName physicalSource = new TableName(
                InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, "test", "physical_source");
        TableName cteSource = new TableName(
                InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, "test", "source_cte");

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkSelectOnUnresolvedTableLikeObject(
                    connectContext, physicalSource), Mockito.times(1));
            authorizer.verify(() -> Authorizer.checkSelectOnUnresolvedTableLikeObject(
                    connectContext, cteSource), Mockito.never());
        }
    }

    @Test
    public void testDeniedCreateViewWrappersDoNotReachAnalyzer() {
        List<StatementBase> statements = List.of(
                parse("CREATE VIEW denied_view AS SELECT 1"),
                parse("CREATE OR REPLACE VIEW denied_view AS SELECT 1"));
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkDbAction(
                            connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                            "test", PrivilegeType.CREATE_VIEW))
                    .thenThrow(new SecurityException("CREATE_VIEW denied"));
            authorizer.clearInvocations();

            for (StatementBase statement : statements) {
                Assertions.assertThrows(SecurityException.class,
                        () -> StatementPlanner.plan(statement, connectContext));
            }
            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    "test", PrivilegeType.CREATE_VIEW), Mockito.times(statements.size()));
        }
    }

    @Test
    public void testDeniedAlterViewDoesNotReachAnalyzer() {
        StatementBase statement = parse("ALTER VIEW denied_view AS SELECT 1");
        AtomicInteger analyzerCalls = mockAnalyzer();
        TableName target = new TableName(
                InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, "test", "denied_view");

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkViewAction(
                            connectContext, target, PrivilegeType.ALTER))
                    .thenThrow(new SecurityException("ALTER VIEW denied"));
            authorizer.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkViewAction(
                    connectContext, target, PrivilegeType.ALTER), Mockito.times(1));
        }
    }

    @Test
    public void testDeniedAsyncMaterializedViewDoesNotReachAnalyzer() {
        StatementBase statement = parse(
                "CREATE MATERIALIZED VIEW denied_async_mv DISTRIBUTED BY HASH(v1) " +
                        "REFRESH MANUAL AS SELECT v1 FROM t0");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkDbAction(
                            connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                            "test", PrivilegeType.CREATE_MATERIALIZED_VIEW))
                    .thenThrow(new SecurityException("CREATE_MATERIALIZED_VIEW denied"));
            authorizer.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    "test", PrivilegeType.CREATE_MATERIALIZED_VIEW), Mockito.times(1));
        }
    }

    @Test
    public void testDeniedSubmitInsertDoesNotReachAnalyzer() {
        StatementBase statement = parse(
                "SUBMIT TASK denied_task_insert AS INSERT INTO t0 VALUES (1, 2, 3)");
        AtomicInteger analyzerCalls = mockAnalyzer();
        TableName target = new TableName(
                InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, "test", "t0");

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            connectContext, target, PrivilegeType.INSERT))
                    .thenThrow(new SecurityException("INSERT denied"));
            authorizer.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    connectContext, target, PrivilegeType.INSERT), Mockito.times(1));
        }
    }

    @Test
    public void testOrdinaryExternalTargetKeepsExistingAnalyzerPath() {
        StatementBase statement = parse(
                "CREATE TABLE cold_catalog.db.external_ctas AS SELECT 1");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    Mockito.eq(connectContext), Mockito.anyString(), Mockito.anyString(),
                    Mockito.eq(PrivilegeType.CREATE_TABLE)), Mockito.never());
        }
    }

    @Test
    public void testBypassContinuesWithoutEarlyDdlAuthorization() {
        StatementBase statement = parse("CREATE TABLE bypass_ctas AS SELECT 1");
        AtomicInteger analyzerCalls = mockAnalyzer();
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    Mockito.eq(connectContext), Mockito.anyString(), Mockito.anyString(),
                    Mockito.eq(PrivilegeType.CREATE_TABLE)), Mockito.never());
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
