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

package com.starrocks.sql.analyzer;

import com.starrocks.common.ErrorCode;
import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.ast.PrepareStmt;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.parser.SqlParser;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class PrepareAnalyzerRangerManagedQueryAuthorizationTest {
    @Test
    public void testManagedExternalIoIsDeniedBeforeAnalyzer() {
        ConnectContext context = new ConnectContext();
        Map<String, String> statements = new LinkedHashMap<>();
        statements.put(
                "PREPARE managed_files FROM SELECT * FROM " +
                        "FILES('path' = 'file:///__managed_prepare_missing__', 'format' = 'parquet')",
                "FILES");
        statements.put(
                "PREPARE managed_outfile FROM " +
                        "SELECT 1 INTO OUTFILE 'file:///__managed_prepare_outfile__' FORMAT AS CSV",
                "OUTFILE");
        AtomicInteger analyzerCalls = mockAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(true);

            for (Map.Entry<String, String> testCase : statements.entrySet()) {
                PrepareStmt statement = parse(testCase.getKey(), context);
                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> new PrepareAnalyzer(context).analyze(statement));
                Assertions.assertTrue(exception.getMessage().contains("Ranger-managed query: " + testCase.getValue()),
                        exception.getMessage());
            }
            Assertions.assertEquals(0, analyzerCalls.get());
        }
    }

    @Test
    public void testOrdinaryQueryContinuesToAnalyzer() {
        ConnectContext context = new ConnectContext();
        PrepareStmt statement = parse("PREPARE ordinary_query FROM SELECT 1", context);
        AtomicInteger analyzerCalls = mockSuccessfulAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(false);
            authorizer.when(() -> Authorizer.check(Mockito.any(StatementBase.class), Mockito.eq(context)))
                    .thenAnswer(invocation -> null);

            new PrepareAnalyzer(context).analyze(statement);
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(() -> Authorizer.check(statement.getInnerStmt(), context));
        }
    }

    @Test
    public void testDeniedTableAndViewMetadataAreAuthorizedAfterAnalysis() {
        ConnectContext context = new ConnectContext();
        Map<String, String> statements = new LinkedHashMap<>();
        statements.put("denied table", "PREPARE denied_table FROM SELECT secret FROM private_table");
        statements.put("denied view", "PREPARE denied_view FROM SELECT secret FROM private_view");
        AtomicInteger analyzerCalls = mockSuccessfulAnalyzer();
        ErrorReportException denial = ErrorReportException.report(
                ErrorCode.ERR_ACCESS_DENIED, "SELECT", "TABLE", " private_relation", "NONE", "NONE");

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(false);
            authorizer.when(() -> Authorizer.check(Mockito.any(StatementBase.class), Mockito.eq(context)))
                    .thenThrow(denial);

            for (Map.Entry<String, String> testCase : statements.entrySet()) {
                PrepareStmt statement = parse(testCase.getValue(), context);
                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> new PrepareAnalyzer(context).analyze(statement), testCase.getKey());
                Assertions.assertTrue(exception.getMessage().contains("SELECT"), exception.getMessage());
            }
            Assertions.assertEquals(2, analyzerCalls.get());
        }
    }

    @Test
    public void testBypassQuerySkipsPostAnalysisAuthorization() {
        ConnectContext context = new ConnectContext();
        context.setBypassAuthorizerCheck(true);
        PrepareStmt statement = parse("PREPARE bypass_query FROM SELECT 1", context);
        AtomicInteger analyzerCalls = mockSuccessfulAnalyzer();

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            new PrepareAnalyzer(context).analyze(statement);
            Assertions.assertEquals(1, analyzerCalls.get());
            authorizer.verify(
                    () -> Authorizer.check(Mockito.any(StatementBase.class), Mockito.eq(context)), Mockito.never());
        }
    }

    private static PrepareStmt parse(String sql, ConnectContext context) {
        return (PrepareStmt) SqlParser.parse(sql, context.getSessionVariable()).get(0);
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

    private static AtomicInteger mockSuccessfulAnalyzer() {
        AtomicInteger calls = new AtomicInteger();
        new MockUp<Analyzer>() {
            @Mock
            public void analyze(StatementBase statement, ConnectContext context) {
                calls.incrementAndGet();
            }
        };
        return calls;
    }

    private static class StopAnalysisException extends RuntimeException {
    }
}
