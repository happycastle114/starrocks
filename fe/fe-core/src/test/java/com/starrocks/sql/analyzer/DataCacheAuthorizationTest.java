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

import com.starrocks.analysis.TableName;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.datacache.DataCacheMgr;
import com.starrocks.qe.ConnectContext;
import com.starrocks.qe.SessionVariable;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.parser.SqlParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class DataCacheAuthorizationTest {
    @Test
    public void testLifecycleDenialDoesNotReachMetadataOrRuleManager() {
        ConnectContext context = new ConnectContext();
        StatementBase[] statements = new StatementBase[] {
                parse("CREATE DATACACHE RULE *.*.* PRIORITY = -1"),
                parse("DROP DATACACHE RULE 7"),
                parse("CLEAR DATACACHE RULES")};

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalStateMgr = Mockito.mockStatic(GlobalStateMgr.class);
                MockedStatic<DataCacheMgr> dataCacheMgr = Mockito.mockStatic(DataCacheMgr.class)) {
            authorizer.when(() -> Authorizer.checkSystemAction(context, PrivilegeType.OPERATE))
                    .thenThrow(new SecurityException("denied"));

            for (StatementBase statement : statements) {
                Assertions.assertThrows(SecurityException.class,
                        () -> DataCacheStmtAnalyzer.analyze(statement, context));
            }

            globalStateMgr.verifyNoInteractions();
            dataCacheMgr.verifyNoInteractions();
        }
    }

    @Test
    public void testConcreteTargetVisibilityPrecedesMetadataResolution() {
        ConnectContext context = new ConnectContext();
        StatementBase statement = parse(
                "CREATE DATACACHE RULE hidden_catalog.hidden_db.hidden_table PRIORITY = -1");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalStateMgr = Mockito.mockStatic(GlobalStateMgr.class);
                MockedStatic<DataCacheMgr> dataCacheMgr = Mockito.mockStatic(DataCacheMgr.class)) {
            authorizer.when(() -> Authorizer.checkAnyActionOnTable(
                            Mockito.eq(context), Mockito.any(TableName.class)))
                    .thenThrow(new SecurityException("hidden target"));

            Assertions.assertThrows(SecurityException.class,
                    () -> DataCacheStmtAnalyzer.analyze(statement, context));

            authorizer.verify(() -> Authorizer.checkSystemAction(context, PrivilegeType.OPERATE));
            authorizer.verify(() -> Authorizer.checkAnyActionOnTable(
                    context, new TableName("hidden_catalog", "hidden_db", "hidden_table")));
            globalStateMgr.verifyNoInteractions();
            dataCacheMgr.verifyNoInteractions();
        }
    }

    @Test
    public void testWildcardRuleSkipsTargetVisibilityAndReachesMetadataOnlyAfterOperate() {
        ConnectContext context = new ConnectContext();
        StatementBase statement = parse("CREATE DATACACHE RULE *.*.* PRIORITY = -1");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalStateMgr = Mockito.mockStatic(GlobalStateMgr.class);
                MockedStatic<DataCacheMgr> dataCacheMgr = Mockito.mockStatic(DataCacheMgr.class)) {
            globalStateMgr.when(GlobalStateMgr::getCurrentState)
                    .thenThrow(new SecurityException("metadata resolution reached"));

            Assertions.assertThrows(SecurityException.class,
                    () -> DataCacheStmtAnalyzer.analyze(statement, context));

            authorizer.verify(() -> Authorizer.checkSystemAction(context, PrivilegeType.OPERATE));
            authorizer.verifyNoMoreInteractions();
            dataCacheMgr.verifyNoInteractions();
        }
    }

    @Test
    public void testInvalidPositivePriorityRemainsRejectedBeforeTargetResolution() {
        ConnectContext context = new ConnectContext();
        StatementBase statement = parse(
                "CREATE DATACACHE RULE hidden_catalog.hidden_db.hidden_table PRIORITY = 1");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalStateMgr = Mockito.mockStatic(GlobalStateMgr.class);
                MockedStatic<DataCacheMgr> dataCacheMgr = Mockito.mockStatic(DataCacheMgr.class)) {
            SemanticException exception = Assertions.assertThrows(SemanticException.class,
                    () -> DataCacheStmtAnalyzer.analyze(statement, context));

            Assertions.assertTrue(exception.getMessage().contains("priority = -1"));
            authorizer.verify(() -> Authorizer.checkSystemAction(context, PrivilegeType.OPERATE));
            authorizer.verifyNoMoreInteractions();
            globalStateMgr.verifyNoInteractions();
            dataCacheMgr.verifyNoInteractions();
        }
    }

    private static StatementBase parse(String sql) {
        return SqlParser.parseOneWithStarRocksDialect(sql, new SessionVariable());
    }
}
