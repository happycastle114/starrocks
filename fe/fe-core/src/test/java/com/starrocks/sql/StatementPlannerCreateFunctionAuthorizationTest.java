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
import com.starrocks.sql.analyzer.AuthorizerStmtVisitor;
import com.starrocks.sql.analyzer.CreateFunctionAnalyzer;
import com.starrocks.sql.ast.CreateFunctionStmt;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.sql.plan.PlanTestBase;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.concurrent.atomic.AtomicInteger;

public class StatementPlannerCreateFunctionAuthorizationTest extends PlanTestBase {
    private static final String REMOTE_PROPERTIES = " PROPERTIES (" +
            "'type' = 'StarrocksJar', " +
            "'symbol' = 'com.example.NeverLoad', " +
            "'file' = 'https://127.0.0.1:1/never-load.jar')";

    @Test
    public void testDeniedLocalFunctionDoesNotReachAnalyzer() {
        CreateFunctionStmt statement = parse(
                "CREATE FUNCTION preauth_local(INT) RETURNS INT" + REMOTE_PROPERTIES);
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.check(statement, connectContext))
                    .thenThrow(new SecurityException("denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
            Assertions.assertEquals("test", statement.getFunctionName().getDb());
            authorizer.verify(() -> Authorizer.check(statement, connectContext), Mockito.times(1));
        }
    }

    @Test
    public void testDeniedGlobalFunctionDoesNotReachAnalyzer() {
        CreateFunctionStmt statement = parse(
                "CREATE GLOBAL FUNCTION preauth_global(INT) RETURNS INT" + REMOTE_PROPERTIES);
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.check(statement, connectContext))
                    .thenThrow(new SecurityException("denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(0, analyzerCalls.get());
            Assertions.assertTrue(statement.getFunctionName().isGlobalFunction());
            authorizer.verify(() -> Authorizer.check(statement, connectContext), Mockito.times(1));
        }
    }

    @Test
    public void testAuthorizedFunctionIsCheckedOnceThenAnalyzed() {
        CreateFunctionStmt statement = parse(
                "CREATE FUNCTION preauth_authorized(INT) RETURNS INT" + REMOTE_PROPERTIES);
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            Assertions.assertDoesNotThrow(() -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            Assertions.assertEquals("test", statement.getFunctionName().getDb());
            authorizer.verify(() -> Authorizer.check(statement, connectContext), Mockito.times(1));
        }
    }

    @Test
    public void testBypassContinuesAnalysisWithoutAuthorization() {
        CreateFunctionStmt statement = parse(
                "CREATE FUNCTION preauth_bypass(INT) RETURNS INT" + REMOTE_PROPERTIES);
        AtomicInteger analyzerCalls = mockAnalyzer();
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertDoesNotThrow(() -> StatementPlanner.plan(statement, connectContext));
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.check(statement, connectContext), Mockito.never());
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
        }
    }

    @Test
    public void testLocalAndGlobalUseExactCreatePrivileges() {
        CreateFunctionStmt local = parse(
                "CREATE FUNCTION preauth_privilege(INT) RETURNS INT" + REMOTE_PROPERTIES);
        local.getFunctionName().analyze("test");
        CreateFunctionStmt global = parse(
                "CREATE GLOBAL FUNCTION preauth_global_privilege(INT) RETURNS INT" + REMOTE_PROPERTIES);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            AuthorizerStmtVisitor visitor = new AuthorizerStmtVisitor();
            visitor.check(local, connectContext);
            visitor.check(global, connectContext);

            authorizer.verify(() -> Authorizer.checkDbAction(
                    connectContext, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    "test", PrivilegeType.CREATE_FUNCTION), Mockito.times(1));
            authorizer.verify(() -> Authorizer.checkSystemAction(
                    connectContext, PrivilegeType.CREATE_GLOBAL_FUNCTION), Mockito.times(1));
        }
    }

    private static CreateFunctionStmt parse(String sql) {
        return (CreateFunctionStmt) SqlParser.parse(sql, connectContext.getSessionVariable()).get(0);
    }

    private static AtomicInteger mockAnalyzer() {
        AtomicInteger calls = new AtomicInteger();
        new MockUp<CreateFunctionAnalyzer>() {
            @Mock
            public void analyze(CreateFunctionStmt statement, com.starrocks.qe.ConnectContext context) {
                calls.incrementAndGet();
            }
        };
        return calls;
    }
}
