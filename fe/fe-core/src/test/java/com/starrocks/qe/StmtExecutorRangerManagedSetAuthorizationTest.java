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

package com.starrocks.qe;

import com.starrocks.common.ErrorReportException;
import com.starrocks.sql.analyzer.Analyzer;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.analyzer.StorageAccessException;
import com.starrocks.sql.ast.QueryStatement;
import com.starrocks.sql.ast.SetStmt;
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

public class StmtExecutorRangerManagedSetAuthorizationTest extends PlanTestBase {
    private static final String FILES_RELATION =
            "FILES('path' = 'file:///__managed_set_missing__', 'format' = 'parquet')";

    @Test
    public void testManagedSetSubqueryIsDeniedBeforeCalculationAnalyzer() {
        SetStmt statement = (SetStmt) parse("SET @managed_value = (SELECT COUNT(*) FROM " + FILES_RELATION + ")");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS);
                var guard = connectContext.bindScope()) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                    () -> new SetExecutor(connectContext, statement).execute());
            Assertions.assertTrue(exception.getMessage().contains("Ranger-managed query: FILES"),
                    exception.getMessage());
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testManagedSetUserVariableHintIsDeniedBeforeCalculationAnalyzer() {
        QueryStatement statement = (QueryStatement) parse(
                "SELECT /*+ SET_USER_VARIABLE(@managed_value=(SELECT COUNT(*) FROM " +
                        FILES_RELATION + ")) */ 1");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                    () -> new StmtExecutor(connectContext, statement).processQueryScopeHint());
            Assertions.assertTrue(exception.getMessage().contains("Ranger-managed query:"),
                    exception.getMessage());
            Assertions.assertTrue(exception.getMessage().contains("SET_USER_VARIABLE"),
                    exception.getMessage());
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testOrdinarySetSubqueryKeepsExistingCalculationPath() {
        SetStmt statement = (SetStmt) parse("SET @ordinary_value = (SELECT COUNT(*) FROM " + FILES_RELATION + ")");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS);
                var guard = connectContext.bindScope()) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(false);

            StorageAccessException exception = Assertions.assertThrows(StorageAccessException.class,
                    () -> new SetExecutor(connectContext, statement).execute());
            Assertions.assertFalse(exception.getMessage().contains("Ranger-managed query"), exception.getMessage());
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testBypassSetSubqueryKeepsExistingCalculationPath() {
        SetStmt statement = (SetStmt) parse("SET @bypass_value = (SELECT COUNT(*) FROM " + FILES_RELATION + ")");
        AtomicInteger analyzerCalls = mockAnalyzer();
        connectContext.setBypassAuthorizerCheck(true);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                var guard = connectContext.bindScope()) {
            StorageAccessException exception = Assertions.assertThrows(StorageAccessException.class,
                    () -> new SetExecutor(connectContext, statement).execute());
            Assertions.assertFalse(exception.getMessage().contains("Ranger-managed query"), exception.getMessage());
            Assertions.assertEquals(0, analyzerCalls.get());
            authorizer.verifyNoInteractions();
        } finally {
            connectContext.setBypassAuthorizerCheck(false);
        }
    }

    private static StatementBase parse(String sql) {
        return SqlParser.parse(sql, connectContext.getSessionVariable()).get(0);
    }

    private static AtomicInteger mockAnalyzer() {
        AtomicInteger calls = new AtomicInteger();
        new MockUp<Analyzer>() {
            @Mock
            public void analyze(StatementBase statement, ConnectContext context) {
                calls.incrementAndGet();
                throw new StopAnalysisException();
            }
        };
        return calls;
    }

    private static class StopAnalysisException extends RuntimeException {
    }
}
