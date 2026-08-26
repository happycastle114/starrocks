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
import com.starrocks.sql.ast.DeleteStmt;
import com.starrocks.sql.ast.DmlStmt;
import com.starrocks.sql.ast.InsertStmt;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.ast.StreamLoadStmt;
import com.starrocks.sql.ast.UpdateStmt;
import com.starrocks.sql.parser.NodePosition;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.sql.plan.PlanTestBase;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.concurrent.atomic.AtomicInteger;

public class StatementPlannerDmlAuthorizationTest extends PlanTestBase {
    @Test
    public void testDeniedInsertDoesNotBeginTransaction() {
        assertDeniedTargetDoesNotBeginTransaction(
                parse("INSERT INTO t0 VALUES (1, 2, 3)"), PrivilegeType.INSERT);
    }

    @Test
    public void testDeniedUpdateDoesNotBeginTransaction() {
        assertDeniedTargetDoesNotBeginTransaction(
                parse("UPDATE t0 SET v1 = 1 WHERE v2 = 2"), PrivilegeType.UPDATE);
    }

    @Test
    public void testDeniedDeleteDoesNotBeginTransaction() {
        assertDeniedTargetDoesNotBeginTransaction(
                parse("DELETE FROM t0 WHERE v1 = 1"), PrivilegeType.DELETE);
    }

    @Test
    public void testAuthorizedDmlNormalizesTargetBeforeTransaction() {
        DmlStmt statement = parse("INSERT INTO t0 VALUES (1, 2, 3)");
        AtomicInteger beginCalls = new AtomicInteger();
        AtomicInteger analyzeCalls = new AtomicInteger();
        mockPlannerBoundaries(beginCalls, analyzeCalls, true);

        Assertions.assertThrows(StopPlanningException.class,
                () -> StatementPlanner.plan(statement, connectContext));
        Assertions.assertEquals(1, beginCalls.get());
        Assertions.assertEquals(1, analyzeCalls.get());
        Assertions.assertEquals(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                statement.getTableName().getCatalog());
        Assertions.assertEquals("test", statement.getTableName().getDb());
    }

    @Test
    public void testBypassBeginsTransactionWithoutAuthorization() {
        DmlStmt statement = parse("INSERT INTO t0 VALUES (1, 2, 3)");
        AtomicInteger beginCalls = new AtomicInteger();
        AtomicInteger analyzeCalls = new AtomicInteger();
        mockPlannerBoundaries(beginCalls, analyzeCalls, true);
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, beginCalls.get());
            Assertions.assertEquals(1, analyzeCalls.get());
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    Mockito.eq(connectContext), Mockito.any(TableName.class), Mockito.eq(PrivilegeType.INSERT)),
                    Mockito.never());
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
        }
    }

    @Test
    public void testDmlUsesExactTargetPrivileges() {
        assertExactTargetPrivilege(parse("INSERT INTO t0 VALUES (1, 2, 3)"), PrivilegeType.INSERT);
        assertExactTargetPrivilege(parse("UPDATE t0 SET v1 = 1 WHERE v2 = 2"), PrivilegeType.UPDATE);
        assertExactTargetPrivilege(parse("DELETE FROM t0 WHERE v1 = 1"), PrivilegeType.DELETE);
    }

    @Test
    public void testManagedColdExternalTargetUsesNameOnlyCheck() {
        DmlStmt statement = parse("INSERT INTO cold_catalog.db.target VALUES (1)");
        AtomicInteger beginCalls = new AtomicInteger();
        AtomicInteger analyzeCalls = new AtomicInteger();
        mockPlannerBoundaries(beginCalls, analyzeCalls, false);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            connectContext, statement.getTableName(), PrivilegeType.INSERT))
                    .thenThrow(new SecurityException("managed external INSERT denied"));
            authorizer.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, beginCalls.get());
            Assertions.assertEquals(0, analyzeCalls.get());
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    connectContext, statement.getTableName(), PrivilegeType.INSERT), Mockito.times(1));
            authorizer.verify(() -> Authorizer.checkTableAction(
                    Mockito.eq(connectContext), Mockito.any(TableName.class), Mockito.eq(PrivilegeType.INSERT)),
                    Mockito.never());
        }
    }

    @Test
    public void testOrdinaryColdExternalTargetKeepsExistingPath() {
        DmlStmt statement = parse("INSERT INTO cold_catalog.db.target VALUES (1)");
        AtomicInteger beginCalls = new AtomicInteger();
        AtomicInteger analyzeCalls = new AtomicInteger();
        mockPlannerBoundaries(beginCalls, analyzeCalls, true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, beginCalls.get());
            Assertions.assertEquals(1, analyzeCalls.get());
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    Mockito.eq(connectContext), Mockito.any(TableName.class), Mockito.eq(PrivilegeType.INSERT)),
                    Mockito.never());
        }
    }

    @Test
    public void testStreamLoadKeepsExistingTransactionPath() {
        StreamLoadStmt statement = new StreamLoadStmt(new TableName("test", "t0"), NodePosition.ZERO);
        AtomicInteger beginCalls = new AtomicInteger();
        new MockUp<StatementPlanner>() {
            @Mock
            public void beginTransaction(DmlStmt ignored, ConnectContext context) {
                beginCalls.incrementAndGet();
                throw new StopPlanningException();
            }
        };

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, beginCalls.get());
            authorizer.verifyNoInteractions();
        }
    }

    private static void assertDeniedTargetDoesNotBeginTransaction(DmlStmt statement, PrivilegeType privilegeType) {
        AtomicInteger beginCalls = new AtomicInteger();
        AtomicInteger analyzeCalls = new AtomicInteger();
        mockPlannerBoundaries(beginCalls, analyzeCalls, false);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            Mockito.eq(connectContext), Mockito.any(TableName.class), Mockito.eq(privilegeType)))
                    .thenThrow(new SecurityException(privilegeType + " denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, beginCalls.get());
            Assertions.assertEquals(0, analyzeCalls.get());
        }
    }

    private static void assertExactTargetPrivilege(DmlStmt statement, PrivilegeType privilegeType) {
        AtomicInteger beginCalls = new AtomicInteger();
        AtomicInteger analyzeCalls = new AtomicInteger();
        mockPlannerBoundaries(beginCalls, analyzeCalls, true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            connectContext, statement.getTableName(), privilegeType))
                    .thenAnswer(invocation -> null);
            authorizer.clearInvocations();

            Assertions.assertThrows(StopPlanningException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    connectContext, statement.getTableName(), privilegeType), Mockito.times(1));
            Assertions.assertEquals(1, beginCalls.get());
            Assertions.assertEquals(1, analyzeCalls.get());
        }
    }

    private static DmlStmt parse(String sql) {
        StatementBase statement = SqlParser.parse(sql, connectContext.getSessionVariable()).get(0);
        if (statement instanceof InsertStmt || statement instanceof UpdateStmt || statement instanceof DeleteStmt) {
            return (DmlStmt) statement;
        }
        throw new AssertionError("expected DML statement");
    }

    private static void mockPlannerBoundaries(AtomicInteger beginCalls, AtomicInteger analyzeCalls,
                                              boolean stopDuringAnalysis) {
        new MockUp<StatementPlanner>() {
            @Mock
            public void beginTransaction(DmlStmt statement, ConnectContext context) {
                beginCalls.incrementAndGet();
            }

            @Mock
            public boolean analyzeStatement(StatementBase statement, ConnectContext context,
                                            PlannerMetaLocker locker) {
                analyzeCalls.incrementAndGet();
                if (stopDuringAnalysis) {
                    throw new StopPlanningException();
                }
                return false;
            }

            @Mock
            public void unLock(PlannerMetaLocker locker) {
            }
        };
    }

    private static class StopPlanningException extends RuntimeException {
    }
}
