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

import com.starrocks.authorization.PrivilegeType;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.analyzer.PipeAnalyzer;
import com.starrocks.sql.ast.pipe.CreatePipeStmt;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.sql.plan.PlanTestBase;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.concurrent.atomic.AtomicInteger;

public class StatementPlannerCreatePipeAuthorizationTest extends PlanTestBase {
    private static final String CREATE_PIPE_SQL =
            "CREATE PIPE preauth_pipe AS INSERT INTO t0 SELECT * FROM FILES(" +
                    "'path' = 's3://never-load/*', 'format' = 'parquet')";

    @Test
    public void testDeniedCreatePipeDoesNotReachAnalyzer() {
        CreatePipeStmt statement = parse();
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkDbAction(
                            Mockito.eq(connectContext), Mockito.anyString(), Mockito.nullable(String.class),
                            Mockito.eq(PrivilegeType.CREATE_PIPE)))
                    .thenThrow(new SecurityException("CREATE_PIPE denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testDeniedPipeInsertDoesNotReachAnalyzer() {
        CreatePipeStmt statement = parse();
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.checkDbAction(
                            Mockito.eq(connectContext), Mockito.anyString(), Mockito.nullable(String.class),
                            Mockito.eq(PrivilegeType.CREATE_PIPE)))
                    .thenAnswer(invocation -> null);
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            Mockito.eq(connectContext), Mockito.any(), Mockito.eq(PrivilegeType.INSERT)))
                    .thenThrow(new SecurityException("INSERT denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testAuthorizedPipeIsCheckedOnceThenAnalyzed() {
        CreatePipeStmt statement = parse();
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.check(statement, connectContext)).thenAnswer(invocation -> null);
            authorizer.when(() -> Authorizer.checkDbAction(
                            connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                            "test", PrivilegeType.CREATE_PIPE))
                    .thenAnswer(invocation -> null);
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            connectContext, statement.getInsertStmt().getTableName(), PrivilegeType.INSERT))
                    .thenAnswer(invocation -> null);
            authorizer.when(() -> Authorizer.check(statement.getInsertStmt(), connectContext))
                    .thenAnswer(invocation -> null);
            authorizer.clearInvocations();

            Assertions.assertDoesNotThrow(() -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            Assertions.assertEquals("test", statement.getPipeName().getDbName());
            Assertions.assertEquals("test", statement.getInsertStmt().getTableName().getDb());
            Assertions.assertEquals(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    statement.getInsertStmt().getTableName().getCatalog());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    "test", PrivilegeType.CREATE_PIPE), Mockito.times(1));
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    connectContext, statement.getInsertStmt().getTableName(), PrivilegeType.INSERT), Mockito.times(1));
        }
    }

    @Test
    public void testBypassContinuesAnalysisWithoutAuthorization() {
        CreatePipeStmt statement = parse();
        AtomicInteger analyzerCalls = mockAnalyzer();
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertDoesNotThrow(() -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.checkDbAction(
                    Mockito.eq(connectContext), Mockito.anyString(), Mockito.nullable(String.class),
                    Mockito.eq(PrivilegeType.CREATE_PIPE)), Mockito.never());
            authorizer.verify(() -> Authorizer.checkTableActionByName(
                    Mockito.eq(connectContext), Mockito.any(), Mockito.eq(PrivilegeType.INSERT)), Mockito.never());
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
        }
    }

    private static CreatePipeStmt parse() {
        return (CreatePipeStmt) SqlParser.parse(CREATE_PIPE_SQL, connectContext.getSessionVariable()).get(0);
    }

    private static AtomicInteger mockAnalyzer() {
        AtomicInteger calls = new AtomicInteger();
        new MockUp<PipeAnalyzer>() {
            @Mock
            public void analyze(CreatePipeStmt statement, com.starrocks.qe.ConnectContext context) {
                calls.incrementAndGet();
            }
        };
        return calls;
    }
}
