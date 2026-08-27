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

package com.starrocks.authorization;

import com.starrocks.analysis.TableName;
import com.starrocks.catalog.MaterializedView;
import com.starrocks.catalog.View;
import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.ast.QueryStatement;
import com.starrocks.sql.ast.SelectList;
import com.starrocks.sql.ast.SelectRelation;
import com.starrocks.sql.ast.TableRelation;
import com.starrocks.sql.ast.UserIdentity;
import com.starrocks.sql.ast.ViewRelation;
import com.starrocks.sql.parser.SqlParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;

public class RangerManagedViewSecurityTest {
    private static final String MANAGED_USER = "flight_sql_ci";

    @Test
    public void testBaseAuthorizationAppliesToBothSecurityModes() {
        ConnectContext context = context(MANAGED_USER);
        QueryStatement noneDefinition = parse("SELECT payload FROM ranger_other.denied_events");
        QueryStatement invokerDefinition = parse("SELECT payload FROM ranger_other.denied_events");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(true);
            authorizer.when(() -> Authorizer.check(noneDefinition, context))
                    .thenThrow(new SecurityException("base denied"));
            authorizer.when(() -> Authorizer.check(invokerDefinition, context))
                    .thenThrow(new SecurityException("base denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> ColumnPrivilege.check(context, throughView(noneDefinition, false, 1), List.of()));
            Assertions.assertThrows(SecurityException.class,
                    () -> ColumnPrivilege.check(context, throughView(invokerDefinition, true, 2), List.of()));
            Assertions.assertTrue(context.getViewExpansionPath().isEmpty());
        }
    }

    @Test
    public void testManagedMaterializedViewsAlwaysFailClosed() {
        ConnectContext context = context(MANAGED_USER);
        List<QueryStatement> definitions = List.of(
                parse("SELECT channel_id, payload FROM gateway_test.events"),
                parse("SELECT 'channel-a' AS channel_id, payload FROM gateway_test.events"),
                parse("SELECT channel_id, COUNT(*) FROM gateway_test.events GROUP BY channel_id"),
                parse("SELECT payload FROM ranger_other.denied_events"));

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(true);
            for (int i = 0; i < definitions.size(); i++) {
                QueryStatement definition = definitions.get(i);
                long materializedViewId = 31 + i;
                ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                        () -> ColumnPrivilege.check(
                                context, throughMaterializedView(definition, materializedViewId), List.of()));
                Assertions.assertTrue(exception.getMessage().contains("Ranger-managed materialized view: " +
                        "test.managed_materialized_view_" + materializedViewId), exception.getMessage());
                authorizer.verify(() -> Authorizer.check(definition, context), Mockito.never());
            }
            Assertions.assertTrue(context.getViewExpansionPath().isEmpty());
        }
    }

    @Test
    public void testOrdinaryMaterializedViewIsUnchanged() {
        ConnectContext context = context("ordinary");
        QueryStatement definition = parse("SELECT HOST_NAME()");
        QueryStatement outerQuery = throughMaterializedView(definition, 41);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(false);
            Assertions.assertDoesNotThrow(() -> RangerManagedViewSecurity.check(context, outerQuery));
            authorizer.verify(() -> Authorizer.check(definition, context), Mockito.never());
            Assertions.assertTrue(context.getViewExpansionPath().isEmpty());
        }
    }

    @Test
    public void testForbiddenFunctionsAndFunctionNodes() {
        assertForbidden("SELECT HOST_NAME()", "HOST_NAME");
        assertForbidden("SELECT LOOKUP_STRING('db.tbl', 'key', 'value')", "LOOKUP_STRING");
        assertForbidden("SELECT DICT_MAPPING('db.tbl', 'key')", "DICT_MAPPING");
        assertForbidden("SELECT DICTIONARY_GET('dictionary', 1)", "DICTIONARY_GET");
        assertForbidden("SELECT GET_QUERY_PROFILE('query-id')", "GET_QUERY_PROFILE");
        assertForbidden("SELECT GET_QUERY_DUMP('SELECT 1')", "GET_QUERY_DUMP");
        assertForbidden("SELECT GET_QUERY_DUMP_FROM_QUERY_ID('query-id')", "GET_QUERY_DUMP_FROM_QUERY_ID");
        assertForbidden("SELECT NATIVE_QUERY()", "NATIVE_QUERY");
        assertForbidden("SELECT AI_QUERY()", "AI_QUERY");
        assertForbidden("SELECT SLEEP(3600)", "SLEEP");
        assertForbidden("SELECT INSPECT_FUTURE()", "INSPECT_FUTURE");
        assertForbidden("SELECT * FROM TABLE(list_rowsets(1, 1))", "LIST_ROWSETS");
        assertForbidden("SELECT * FROM FILES(\"path\" = \"s3://bucket/file.parquet\")", "FILES");
    }

    @Test
    public void testForbiddenHints() {
        assertForbidden("SELECT value FROM db.tbl [_META_]", "_META_");
        assertForbidden("SELECT value FROM db.tbl [_BINLOG_]", "_BINLOG_");
        assertForbidden("SELECT value FROM db.tbl [_SYNC_MV_]", "_SYNC_MV_");
        assertForbidden("SELECT value FROM db.tbl [_USE_PK_INDEX_]", "_USE_PK_INDEX_");
        assertForbidden("SELECT value FROM db.tbl [_CACHE_STATS_]", "_CACHE_STATS_");
        assertForbidden("SELECT /*+ SET_VAR(query_timeout = 1) */ 1", "SET_VAR");
        assertForbidden("SELECT /*+ SET_USER_VARIABLE(@a = 1) */ @a", "SET_USER_VARIABLE");
    }

    @Test
    public void testForbiddenRelations() {
        assertForbidden("SELECT table_name FROM information_schema.tables", "INFORMATION_SCHEMA");
        assertForbidden("SELECT * FROM sys.fe_locks", "SYS");
        assertForbidden("SELECT * FROM _statistics_.column_statistics", "_STATISTICS_");
        assertForbidden("SELECT * FROM iceberg.db.`events$files`", "events$files");
        String[] forbiddenMetadataTables = {
                "events$logical_iceberg_metadata", "events$refs", "events$history",
                "events$metadata_log_entries", "events$snapshots", "events$manifests",
                "events$files", "events$partitions"
        };
        for (String table : forbiddenMetadataTables) {
            Assertions.assertTrue(RangerManagedViewSecurity.isForbiddenConnectorMetadataTable(table));
        }
    }

    @Test
    public void testNestedViewAndCteAreValidated() {
        assertForbidden("WITH hidden AS (SELECT HOST_NAME() AS value) SELECT value FROM hidden", "HOST_NAME");

        ConnectContext context = context(MANAGED_USER);
        QueryStatement hiddenDefinition = parse("SELECT HOST_NAME()");
        QueryStatement nestedDefinition = throughView(hiddenDefinition, false, 11);
        QueryStatement outerQuery = throughView(nestedDefinition, true, 12);
        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(true);
            authorizer.when(() -> Authorizer.check(Mockito.any(QueryStatement.class), Mockito.same(context)))
                    .thenAnswer(invocation -> {
                        RangerManagedViewSecurity.check(context, invocation.getArgument(0));
                        return null;
                    });

            ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                    () -> RangerManagedViewSecurity.check(context, outerQuery));
            Assertions.assertTrue(exception.getMessage().contains("HOST_NAME"));
            Assertions.assertTrue(context.getViewExpansionPath().isEmpty());
        }
    }

    @Test
    public void testSafeDefinitionsDirectQueriesAndOrdinaryUsersAreUnchanged() {
        ConnectContext managedContext = context(MANAGED_USER);
        ConnectContext ordinaryContext = context("ordinary");
        QueryStatement safeDefinition = parse("SELECT /* ordinary comment */ ABS(-1), CURRENT_USER()");
        QueryStatement hiddenDefinition = parse("SELECT HOST_NAME()");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(managedContext)).thenReturn(true);
            authorizer.when(() -> Authorizer.isRangerManagedContext(ordinaryContext)).thenReturn(false);

            Assertions.assertDoesNotThrow(
                    () -> RangerManagedViewSecurity.check(managedContext, throughView(safeDefinition, false, 21)));
            Assertions.assertDoesNotThrow(
                    () -> RangerManagedViewSecurity.check(managedContext, hiddenDefinition));
            Assertions.assertDoesNotThrow(
                    () -> RangerManagedViewSecurity.check(ordinaryContext,
                            throughView(hiddenDefinition, false, 22)));

            authorizer.verify(() -> Authorizer.check(safeDefinition, managedContext));
            authorizer.verify(() -> Authorizer.check(hiddenDefinition, ordinaryContext), Mockito.never());
        }
    }

    private static void assertForbidden(String definitionSql, String diagnostic) {
        ConnectContext context = context(MANAGED_USER);
        QueryStatement definition = parse(definitionSql);
        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(true);
            ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class,
                    () -> RangerManagedViewSecurity.check(context, throughView(definition, false, 100)));
            Assertions.assertTrue(exception.getMessage().contains(diagnostic), exception.getMessage());
        }
    }

    private static QueryStatement throughView(QueryStatement definition, boolean security, long viewId) {
        String viewName = "managed_view_" + viewId;
        View view = new View(viewId, viewName, List.of());
        view.setSecurity(security);
        ViewRelation viewRelation = new ViewRelation(
                new TableName("default_catalog", "test", viewName), view, definition);
        SelectRelation select = new SelectRelation(new SelectList(), viewRelation, null, null, null);
        select.setOrderBy(new ArrayList<>());
        return new QueryStatement(select);
    }

    private static QueryStatement throughMaterializedView(QueryStatement definition, long materializedViewId) {
        String viewName = "managed_materialized_view_" + materializedViewId;
        MaterializedView materializedView = Mockito.mock(MaterializedView.class);
        Mockito.when(materializedView.getId()).thenReturn(materializedViewId);
        Mockito.when(materializedView.getName()).thenReturn(viewName);
        TableRelation tableRelation = new TableRelation(
                new TableName("default_catalog", "test", viewName));
        tableRelation.setTable(materializedView);
        SelectRelation select = new SelectRelation(new SelectList(), tableRelation, null, null, null);
        select.setOrderBy(new ArrayList<>());
        return new QueryStatement(select);
    }

    private static QueryStatement parse(String sql) {
        return (QueryStatement) SqlParser.parse(sql, 0).get(0);
    }

    private static ConnectContext context(String user) {
        ConnectContext context = new ConnectContext();
        context.setQualifiedUser(user);
        context.setCurrentUserIdentity(new UserIdentity(user, "%"));
        return context;
    }
}
