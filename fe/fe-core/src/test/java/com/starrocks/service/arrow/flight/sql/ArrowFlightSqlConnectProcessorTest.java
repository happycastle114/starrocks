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

package com.starrocks.service.arrow.flight.sql;

import com.starrocks.sql.analyzer.AnalyzerUtils;
import com.starrocks.sql.ast.Relation;
import com.starrocks.sql.ast.StatementBase;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ArrowFlightSqlConnectProcessorTest {
    private static void assertParseMarksRelationsForPolicyRewrite(String sql, int expected) throws Exception {
        ArrowFlightSqlConnectContext context = new ArrowFlightSqlConnectContext("token");
        ArrowFlightSqlConnectProcessor processor = new ArrowFlightSqlConnectProcessor(context, sql);
        StatementBase parsedStatement = processor.parse(sql, context.getSessionVariable());

        Map<?, Relation> relations = AnalyzerUtils.collectAllTableAndViewRelations(parsedStatement);
        assertEquals(expected, relations.size(), "Unexpected relation count for: " + sql);
        assertTrue(relations.values().stream().allMatch(Relation::isNeedRewrittenByPolicy),
                "Flight parser left a relation unmarked for policy rewrite in: " + sql);
    }

    @Test
    public void testParseMarksRelationsForPolicyRewriteInPlainJoin() throws Exception {
        assertParseMarksRelationsForPolicyRewrite(
                "SELECT * FROM db1.tbl1 JOIN db1.tbl2 ON tbl1.id = tbl2.id", 2);
    }

    @Test
    public void testParseMarksRelationsForPolicyRewriteInParserOwnedQueryExpressions() throws Exception {
        assertParseMarksRelationsForPolicyRewrite(
                "SELECT (SELECT k1 FROM db1.tbl1) FROM db1.tbl2", 2);
        assertParseMarksRelationsForPolicyRewrite(
                "SELECT COUNT(*) FROM db1.tbl1 GROUP BY (SELECT MAX(k1) FROM db1.tbl2)", 2);
        assertParseMarksRelationsForPolicyRewrite(
                "SELECT * FROM db1.tbl1 PIVOT (MAX(k1) FOR k2 IN ('a'))", 1);
        assertParseMarksRelationsForPolicyRewrite(
                "SELECT * FROM UNNEST((SELECT ARRAY_AGG(k1) FROM db1.tbl1))", 1);
        assertParseMarksRelationsForPolicyRewrite(
                "SELECT * FROM TABLE(UNNEST((SELECT ARRAY_AGG(k1) FROM db1.tbl1)))", 1);
        assertParseMarksRelationsForPolicyRewrite(
                "SELECT * FROM (VALUES ((SELECT MAX(k1) FROM db1.tbl1))) v", 1);
    }
}
