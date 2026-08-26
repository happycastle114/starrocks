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
import com.starrocks.sql.analyzer.Analyzer;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.analyzer.AuthorizerStmtVisitor;
import com.starrocks.sql.analyzer.PlannerMetaLocker;
import com.starrocks.sql.analyzer.SemanticException;
import com.starrocks.sql.ast.CreateMaterializedViewStmt;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.sql.plan.PlanTestBase;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.concurrent.atomic.AtomicInteger;

public class StatementPlannerCreateMaterializedViewAuthorizationTest extends PlanTestBase {
    private static final String CREATE_SYNC_MV =
            "CREATE MATERIALIZED VIEW preauth_sync_mv AS " +
                    "SELECT v1, SUM(v2) AS total FROM t0 GROUP BY v1";

    @Test
    public void testDeniedCreateMaterializedViewDoesNotReachAnalyzer() {
        CreateMaterializedViewStmt statement = parse(CREATE_SYNC_MV);
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkDbAction(
                            connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                            "test", PrivilegeType.CREATE_MATERIALIZED_VIEW))
                    .thenThrow(new SecurityException("CREATE_MATERIALIZED_VIEW denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testDeniedSourceSelectDoesNotReachAnalyzer() {
        CreateMaterializedViewStmt statement = parse(CREATE_SYNC_MV);
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkDbAction(
                            connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                            "test", PrivilegeType.CREATE_MATERIALIZED_VIEW))
                    .thenAnswer(invocation -> null);
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            Mockito.eq(connectContext), Mockito.any(TableName.class),
                            Mockito.eq(PrivilegeType.SELECT)))
                    .thenThrow(new SecurityException("SELECT denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testAuthorizedLegacyMaterializedViewContinuesToAnalyzerAndPostAuthorization() {
        CreateMaterializedViewStmt statement = parse(CREATE_SYNC_MV);
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkDbAction(
                            connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                            "test", PrivilegeType.CREATE_MATERIALIZED_VIEW))
                    .thenAnswer(invocation -> null);
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            Mockito.eq(connectContext), Mockito.any(TableName.class),
                            Mockito.eq(PrivilegeType.SELECT)))
                    .thenAnswer(invocation -> null);
            authorizer.when(() -> Authorizer.check(statement, connectContext)).thenAnswer(invocation -> null);
            authorizer.clearInvocations();

            Assertions.assertDoesNotThrow(() -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    "test", PrivilegeType.CREATE_MATERIALIZED_VIEW), Mockito.times(1));
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    connectContext, new TableName(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, "test", "t0"),
                    PrivilegeType.SELECT), Mockito.times(1));
            authorizer.verify(() -> Authorizer.check(statement, connectContext), Mockito.times(1));
        }
    }

    @Test
    public void testLegacyMaterializedViewFilesFailsClosedBeforeAnalyzer() {
        CreateMaterializedViewStmt statement = parse(
                "CREATE MATERIALIZED VIEW preauth_sync_files AS SELECT * FROM " +
                        "FILES('path' = 'file:///__sync_mv_missing__', 'format' = 'parquet')");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkDbAction(
                            connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                            "test", PrivilegeType.CREATE_MATERIALIZED_VIEW))
                    .thenAnswer(invocation -> null);

            SemanticException exception = Assertions.assertThrows(SemanticException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertTrue(exception.getMessage().contains("direct query from table"), exception.getMessage());
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testBypassKeepsLegacyMaterializedViewAnalyzerPath() {
        CreateMaterializedViewStmt statement = parse(CREATE_SYNC_MV);
        AtomicInteger analyzerCalls = mockAnalyzer();
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertDoesNotThrow(() -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    Mockito.eq(connectContext), Mockito.anyString(), Mockito.anyString(),
                    Mockito.eq(PrivilegeType.CREATE_MATERIALIZED_VIEW)), Mockito.never());
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    Mockito.eq(connectContext), Mockito.any(TableName.class), Mockito.eq(PrivilegeType.SELECT)),
                    Mockito.never());
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
        }
    }

    @Test
    public void testLegacyMaterializedViewPostAuthorizationChecksDatabaseAndSource() {
        CreateMaterializedViewStmt statement = parse(CREATE_SYNC_MV);
        statement.getTableName().normalization(connectContext);
        Analyzer.analyze(statement, connectContext);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            new AuthorizerStmtVisitor().check(statement, connectContext);

            authorizer.verify(() -> Authorizer.checkDbAction(
                    connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    "test", PrivilegeType.CREATE_MATERIALIZED_VIEW), Mockito.times(1));
            authorizer.verify(() -> Authorizer.checkTableAction(
                    connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    "test", "t0", PrivilegeType.SELECT), Mockito.times(1));
        }
    }

    private static CreateMaterializedViewStmt parse(String sql) {
        return (CreateMaterializedViewStmt) SqlParser.parse(sql, connectContext.getSessionVariable()).get(0);
    }

    private static AtomicInteger mockAnalyzer() {
        AtomicInteger calls = new AtomicInteger();
        new MockUp<StatementPlanner>() {
            @Mock
            public boolean analyzeStatement(StatementBase statement, ConnectContext context,
                                            PlannerMetaLocker locker) {
                calls.incrementAndGet();
                return false;
            }

            @Mock
            public void unLock(PlannerMetaLocker locker) {
            }
        };
        return calls;
    }

}
