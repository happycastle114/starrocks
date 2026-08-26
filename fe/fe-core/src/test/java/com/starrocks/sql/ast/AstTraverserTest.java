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

package com.starrocks.sql.ast;

import com.starrocks.authorization.SecurityPolicyRewriteRule;
import com.starrocks.sql.analyzer.AnalyzerUtils;
import com.starrocks.sql.parser.SqlParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AstTraverserTest {
    private static StatementBase parse(String sql) {
        return SqlParser.parse(sql, 0L).get(0);
    }

    private static List<TableRelation> collectTableRelations(StatementBase statement) {
        List<TableRelation> tableRelations = new ArrayList<>();
        new AstTraverser<Void, Void>() {
            @Override
            public Void visitTable(TableRelation node, Void context) {
                tableRelations.add(node);
                return null;
            }
        }.visit(statement);
        return tableRelations;
    }

    private static void assertTablesReachedAndMarked(String sql, int expected) {
        StatementBase statement = parse(sql);
        List<TableRelation> relations = collectTableRelations(statement);
        Assertions.assertEquals(expected, relations.size(),
                "AstTraverser did not reach every table relation in: " + sql);

        Map<?, Relation> collectedRelations = AnalyzerUtils.collectAllTableAndViewRelations(statement);
        Assertions.assertEquals(expected, collectedRelations.size(),
                "AnalyzerUtils did not reach every table relation in: " + sql);

        SecurityPolicyRewriteRule.markRelationsForRewrite(statement);
        Assertions.assertTrue(relations.stream().allMatch(Relation::isNeedRewrittenByPolicy),
                "Security-policy marker did not mark every table relation in: " + sql);
        Assertions.assertTrue(collectedRelations.values().stream().allMatch(Relation::isNeedRewrittenByPolicy),
                "AnalyzerUtils returned a relation not marked for policy rewrite in: " + sql);
    }

    @Test
    public void testReachesRelationsInPlainJoin() {
        assertTablesReachedAndMarked(
                "select * from db1.tbl1 a join db1.tbl2 b on a.k1 = b.k1", 2);
    }

    @Test
    public void testReachesRelationsInParserOwnedQueryExpressions() {
        assertTablesReachedAndMarked("select (select k1 from db1.tbl1) from db1.tbl2", 2);
        assertTablesReachedAndMarked(
                "select count(*) from db1.tbl1 group by (select max(k1) from db1.tbl2)", 2);
        assertTablesReachedAndMarked(
                "select * from db1.tbl1 PIVOT (max(k1) FOR k2 IN ('a'))", 1);
        assertTablesReachedAndMarked(
                "select * from unnest((select array_agg(k1) from db1.tbl1))", 1);
        assertTablesReachedAndMarked(
                "select * from table(unnest((select array_agg(k1) from db1.tbl1)))", 1);
        assertTablesReachedAndMarked(
                "select * from (values ((select max(k1) from db1.tbl1))) v", 1);
    }
}
