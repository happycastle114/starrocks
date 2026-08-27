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

package com.starrocks.analysis;

import com.starrocks.authorization.AccessControlProvider;
import com.starrocks.authorization.AccessController;
import com.starrocks.authorization.AccessDeniedException;
import com.starrocks.authorization.ExternalAccessController;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.common.AnalysisException;
import com.starrocks.common.ErrorReportException;
import com.starrocks.common.jmockit.Deencapsulation;
import com.starrocks.mysql.MysqlCommand;
import com.starrocks.qe.ConnectContext;
import com.starrocks.qe.OriginStatement;
import com.starrocks.qe.PrepareStmtContext;
import com.starrocks.qe.SqlModeHelper;
import com.starrocks.qe.StmtExecutor;
import com.starrocks.sql.analyzer.AstToSQLBuilder;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.ast.ExecuteStmt;
import com.starrocks.sql.ast.PrepareStmt;
import com.starrocks.sql.ast.QueryStatement;
import com.starrocks.sql.ast.SelectRelation;
import com.starrocks.sql.ast.SetStmt;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.ast.TableRelation;
import com.starrocks.sql.ast.UserVariable;
import com.starrocks.sql.common.StarRocksPlannerException;
import com.starrocks.sql.optimizer.LogicalPlanPrinter;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.sql.plan.ExecPlan;
import com.starrocks.utframe.StarRocksAssert;
import com.starrocks.utframe.UtFrameUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PreparedStmtTest{
    private static ConnectContext ctx;
    private static StarRocksAssert starRocksAssert;
    private static String createTable = "CREATE TABLE `prepare_stmt` (\n" +
            "  `c0` varchar(24) NOT NULL COMMENT \"\",\n" +
            "  `c1` decimal128(24, 5) NOT NULL COMMENT \"\",\n" +
            "  `c2` decimal128(24, 2) NOT NULL COMMENT \"\"\n" +
            ") ENGINE=OLAP \n" +
            "DUPLICATE KEY(`c0`)\n" +
            "COMMENT \"OLAP\"\n" +
            "DISTRIBUTED BY HASH(`c0`) BUCKETS 1 \n" +
            "PROPERTIES (\n" +
            "\"replication_num\" = \"1\",\n" +
            "\"in_memory\" = \"false\",\n" +
            "\"storage_format\" = \"DEFAULT\",\n" +
            "\"enable_persistent_index\" = \"true\",\n" +
            "\"replicated_storage\" = \"true\",\n" +
            "\"compression\" = \"LZ4\"\n" +
            "); ";
    private static String createRlsTable = "CREATE TABLE `prepared_rls` (\n" +
            "  `event_id` varchar(24) NOT NULL,\n" +
            "  `channel_id` varchar(24) NOT NULL,\n" +
            "  `event_order` int NOT NULL\n" +
            ") ENGINE=OLAP\n" +
            "DUPLICATE KEY(`event_id`)\n" +
            "DISTRIBUTED BY HASH(`event_id`) BUCKETS 1\n" +
            "PROPERTIES (\"replication_num\" = \"1\");";


    @BeforeAll
    public static void setUp() throws Exception {
        UtFrameUtils.createMinStarRocksCluster();
        ctx = UtFrameUtils.createDefaultCtx();
        starRocksAssert = new StarRocksAssert(ctx);
        starRocksAssert.withDatabase("demo").useDatabase("demo");
        starRocksAssert.withTable(createTable);
        starRocksAssert.withTable(createRlsTable);
    }

    @Test
    public void testParser() throws Exception {
        String sql1 = "PREPARE stmt2 FROM select * from demo.prepare_stmt where c1 = ? and c2 = ?;";
        String sql2 = "PREPARE stmt3 FROM 'select * from demo.prepare_stmt';";
        String sql3 = "execute stmt3;";
        String sql4 = "execute stmt2 using @i;";

        PrepareStmt stmt1 = (PrepareStmt) UtFrameUtils.parseStmtWithNewParser(sql1, ctx);
        PrepareStmt stmt2 = (PrepareStmt) UtFrameUtils.parseStmtWithNewParser(sql2, ctx);
        Assertions.assertEquals(2, stmt1.getParameters().size());
        Assertions.assertEquals(0, stmt2.getParameters().size());
        Assertions.assertThrows(StarRocksPlannerException.class, () -> UtFrameUtils.parseStmtWithNewParser(sql3, ctx));

        ctx.putPreparedStmt("stmt2", new PrepareStmtContext(stmt2, ctx, null));
        Assertions.assertThrows(AnalysisException.class, () -> UtFrameUtils.parseStmtWithNewParser(sql4, ctx));
    }

    @Test
    public void testIsQuery() throws Exception {
        String selectSql = "select * from demo.prepare_stmt";
        QueryStatement queryStatement = (QueryStatement) UtFrameUtils.parseStmtWithNewParser(selectSql, ctx);
        Assertions.assertEquals(true, ctx.isQueryStmt(queryStatement));

        String prepareSql = "PREPARE stmt FROM select * from demo.prepare_stmt";
        PrepareStmt prepareStmt = (PrepareStmt) UtFrameUtils.parseStmtWithNewParser(prepareSql, ctx);
        Assertions.assertEquals(false, ctx.isQueryStmt(prepareStmt));

        ctx.putPreparedStmt("stmt", new PrepareStmtContext(prepareStmt, ctx, null));
        Assertions.assertEquals(true, ctx.isQueryStmt(new ExecuteStmt("stmt", null)));
        Assertions.assertEquals(false, ctx.isQueryStmt(new ExecuteStmt("stmt1", null)));
    }

    @Test
    public void testPrepareEnable() {
        ctx.getSessionVariable().setEnablePrepareStmt(false);
        String prepareSql = "PREPARE stmt1 FROM insert into demo.prepare_stmt values (?, ?, ?, ?);";
        String executeSql = "execute stmt1 using @i, @i;";
        Assertions.assertThrows(StarRocksPlannerException.class, () -> starRocksAssert.query(prepareSql).explainQuery());
        Assertions.assertThrows(StarRocksPlannerException.class, () -> starRocksAssert.query(executeSql).explainQuery());
        ctx.getSessionVariable().setEnablePrepareStmt(true);
        assertDoesNotThrow(() -> starRocksAssert.query(prepareSql));

        // TODO support forward leader for fe
        StatementBase statement = SqlParser.parse(prepareSql, ctx.getSessionVariable()).get(0);
        StmtExecutor executor = new StmtExecutor(ctx, statement);
        Assertions.assertFalse(executor.isForwardToLeader());
    }

    @Test
    public void testPrepareWithSelectConst() throws Exception {
        String sql = "PREPARE stmt1 FROM select ?, ?, ?;";
        PrepareStmt stmt = (PrepareStmt) UtFrameUtils.parseStmtWithNewParser(sql, ctx);
        Assertions.assertEquals(3, stmt.getParameters().size());

        HashSet<Integer> idSet = new HashSet<Integer>();
        for (Expr expr : stmt.getParameters()) {
            Assertions.assertEquals(true, idSet.add(expr.hashCode()));
        }

        Assertions.assertEquals(false, stmt.getParameters().get(0).equals(stmt.getParameters().get(1)));
        Assertions.assertEquals(false, stmt.getParameters().get(1).equals(stmt.getParameters().get(2)));
        Assertions.assertEquals(false, stmt.getParameters().get(0).equals(stmt.getParameters().get(2)));
    }

    @Test
    public void testExecutionUsesPrepareNamespaceAndRestoresUseState() throws Exception {
        String name = "prepare_namespace_stmt";
        PrepareStmt metadataStmt = (PrepareStmt) SqlParser.parse(
                "PREPARE " + name + " FROM 'select c0 from prepare_stmt where c0 = ?'",
                ctx.getSessionVariable()).get(0);
        PrepareStmtContext prepareContext = new PrepareStmtContext(metadataStmt, ctx, null);
        String preparedDatabase = ctx.getDatabase();
        boolean preparedAliasMode = ctx.isRelationAliasCaseInsensitive();
        String callerDatabase = "database_selected_after_prepare";
        boolean callerAliasMode = !preparedAliasMode;

        ctx.setDatabase(callerDatabase);
        ctx.setRelationAliasCaseInSensitive(callerAliasMode);
        ctx.putPreparedStmt(name, prepareContext);
        try {
            PrepareStmt first = prepareContext.instantiate(List.of(new IntLiteral(11)));
            PrepareStmt second = prepareContext.instantiate(List.of(new IntLiteral(22)));
            Assertions.assertNotSame(metadataStmt.getInnerStmt(), first.getInnerStmt());
            Assertions.assertNotSame(first.getInnerStmt(), second.getInnerStmt());
            Assertions.assertNull(metadataStmt.getParameters().get(0).getExpr());

            GeneratedPreparedPlan generated = generatePreparedPlan(name, new IntLiteral(33));
            SelectRelation plannedSelect = (SelectRelation) ((QueryStatement) generated.executor.getParsedStmt())
                    .getQueryRelation();
            Assertions.assertEquals(preparedDatabase,
                    ((TableRelation) plannedSelect.getRelation()).getName().getDb());
            Assertions.assertEquals(callerDatabase, ctx.getDatabase(),
                    "EXECUTE must restore the database selected after PREPARE");
            Assertions.assertEquals(callerAliasMode, ctx.isRelationAliasCaseInsensitive(),
                    "EXECUTE must restore parser-visible session state");
        } finally {
            ctx.removePreparedStmt(name);
            ctx.setDatabase(preparedDatabase);
            ctx.setRelationAliasCaseInSensitive(preparedAliasMode);
        }
    }

    @Test
    public void testExecutionReparseUsesPreparedSessionVariableSnapshot() {
        boolean originalLargeIn = ctx.getSessionVariable().enableLargeInPredicate();
        int originalThreshold = ctx.getSessionVariable().getLargeInPredicateThreshold();
        try {
            ctx.getSessionVariable().setEnableLargeInPredicate(true);
            ctx.getSessionVariable().setLargeInPredicateThreshold(2);
            String sql = "select c0 from prepare_stmt where c0 in ('a', 'b')";
            StatementBase query = SqlParser.parse(sql, ctx.getSessionVariable()).get(0);
            PrepareStmt metadataStmt = new PrepareStmt("parser_snapshot_stmt", query, List.of());
            PrepareStmtContext prepareContext = new PrepareStmtContext(
                    metadataStmt, ctx, null, new OriginStatement(sql, 0));

            // Simulate SET changing parser behavior after PREPARE. EXECUTE reparses under the
            // PREPARE-time snapshot and must restore the caller-visible value afterwards.
            ctx.getSessionVariable().setEnableLargeInPredicate(false);
            PrepareStmt executable = prepareContext.instantiate(List.of());
            SelectRelation select = (SelectRelation) ((QueryStatement) executable.getInnerStmt()).getQueryRelation();

            Assertions.assertInstanceOf(LargeInPredicate.class, select.getPredicate());
            Assertions.assertFalse(ctx.getSessionVariable().enableLargeInPredicate());
        } finally {
            ctx.getSessionVariable().setEnableLargeInPredicate(originalLargeIn);
            ctx.getSessionVariable().setLargeInPredicateThreshold(originalThreshold);
        }
    }

    @Test
    public void testPreparedExecutionReevaluatesChangedPolicy() throws Exception {
        String name = "dynamic_policy_stmt";
        AtomicReference<String> currentPolicy = new AtomicReference<>("prepare_policy");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.getColumnMaskingPolicy(
                            Mockito.any(), Mockito.any(), Mockito.any()))
                    .thenAnswer(invocation -> Map.of("c0", new StringLiteral(currentPolicy.get())));
            authorizer.when(() -> Authorizer.getRowAccessPolicy(Mockito.any(), Mockito.any()))
                    .thenReturn(null);

            // PREPARE may rewrite its metadata copy, but every EXECUTE must start from pristine
            // SQL and apply the policy that is active at that execution boundary.
            PrepareStmt metadataStmt = (PrepareStmt) SqlParser.parse(
                    "PREPARE " + name + " FROM 'select c0 from prepare_stmt where c0 = ?'",
                    ctx.getSessionVariable()).get(0);
            new StmtExecutor(ctx, metadataStmt).execute();
            PrepareStmtContext prepareContext = ctx.getPreparedStmt(name);
            Assertions.assertNotNull(prepareContext);
            Assertions.assertTrue(AstToSQLBuilder.toSQL(metadataStmt.getInnerStmt()).contains("prepare_policy"));

            currentPolicy.set("execute_policy_1");
            GeneratedPreparedPlan firstPlan = generatePreparedPlan(name, new StringLiteral("first"));
            String firstSql = AstToSQLBuilder.toSQL(firstPlan.executor.getParsedStmt());

            currentPolicy.set("execute_policy_2");
            GeneratedPreparedPlan secondPlan = generatePreparedPlan(name, new StringLiteral("second"));
            String secondSql = AstToSQLBuilder.toSQL(secondPlan.executor.getParsedStmt());

            Assertions.assertNotSame(firstPlan.executor.getParsedStmt(), secondPlan.executor.getParsedStmt());
            Assertions.assertTrue(firstSql.contains("execute_policy_1"), firstSql);
            Assertions.assertTrue(secondSql.contains("execute_policy_2"), secondSql);
            Assertions.assertTrue(logicalPlan(firstPlan.execPlan).contains("execute_policy_1"));
            Assertions.assertTrue(logicalPlan(secondPlan.execPlan).contains("execute_policy_2"));
            Assertions.assertFalse(prepareContext.isCached());
            Assertions.assertNull(metadataStmt.getParameters().get(0).getExpr());
        } finally {
            ctx.removePreparedStmt(name);
        }
    }

    @Test
    public void testBinaryPrepareWithRowPolicyKeepsParametersUnboundForMetadata() throws Exception {
        String sql = "select event_id from prepared_rls where event_order > ?";
        PrepareStmt prepareStmt = (PrepareStmt) SqlParser.parse(sql, ctx.getSessionVariable()).get(0);
        prepareStmt.setName("binary_row_policy_stmt");
        prepareStmt.setOrigStmt(new OriginStatement(sql, 0));
        String setTenantSql = "SET @app_channel_id = from_base64('dGVuYW50LWE=')";
        SetStmt setTenant = (SetStmt) SqlParser.parse(setTenantSql, ctx.getSessionVariable()).get(0);
        UserVariable tenantVariable = (UserVariable) setTenant.getSetListItems().get(0);
        tenantVariable.setEvaluatedExpression(
                new VarBinaryLiteral("tenant-a".getBytes(StandardCharsets.UTF_8)));
        ctx.modifyUserVariable(tenantVariable);
        AccessControlProvider accessControlProvider = Authorizer.getInstance();
        AccessController originalAccessControl = accessControlProvider.catalogToAccessControl.get(
                InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME);
        Set<String> checkedColumns = new HashSet<>();
        AtomicReference<String> deniedColumn = new AtomicReference<>();
        AtomicBoolean rowPolicyEnabled = new AtomicBoolean(true);
        ExternalAccessController testAccessControl = new ExternalAccessController() {
            @Override
            public void checkColumnAction(ConnectContext ignoredContext, TableName ignoredTable,
                                          String column, PrivilegeType ignoredPrivilege)
                    throws AccessDeniedException {
                checkedColumns.add(column);
                if (column.equals(deniedColumn.get())) {
                    throw new AccessDeniedException();
                }
            }
        };
        MysqlCommand originalCommand = ctx.getCommand();
        try {
            accessControlProvider.catalogToAccessControl.put(
                    InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, testAccessControl);
            Assertions.assertSame(testAccessControl, accessControlProvider.getAccessControlOrDefault(
                    InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, ctx));
            ctx.setCommand(MysqlCommand.COM_STMT_PREPARE);
            try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(
                    Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
                authorizer.when(() -> Authorizer.getColumnMaskingPolicy(
                                Mockito.any(), Mockito.any(), Mockito.any()))
                        .thenReturn(Map.of());
                authorizer.when(() -> Authorizer.getRowAccessPolicy(Mockito.any(), Mockito.any()))
                        .thenAnswer(invocation -> rowPolicyEnabled.get()
                                ? SqlParser.parseSqlToExpr(
                                        "channel_id = @app_channel_id", SqlModeHelper.MODE_DEFAULT)
                                : null);

                StmtExecutor executor = new StmtExecutor(ctx, prepareStmt);
                assertDoesNotThrow(() -> Deencapsulation.invoke(executor, "generateExecPlan"),
                        "COM_STMT_PREPARE must analyze metadata without translating an unbound parameter");
                authorizer.verify(() -> Authorizer.getRowAccessPolicy(Mockito.any(), Mockito.any()));
                String analyzedSql = AstToSQLBuilder.toSQL(prepareStmt.getInnerStmt());
                Assertions.assertTrue(analyzedSql.contains("app_channel_id"), analyzedSql);
                Assertions.assertEquals(Set.of("channel_id", "event_id", "event_order"), checkedColumns);
                Assertions.assertNull(prepareStmt.getParameters().get(0).getExpr());

                deniedColumn.set("channel_id");
                String wildcardSql = "select * from prepared_rls where event_order > ?";
                PrepareStmt deniedPrepare = (PrepareStmt) SqlParser.parse(
                        wildcardSql, ctx.getSessionVariable()).get(0);
                deniedPrepare.setName("binary_row_policy_denied_stmt");
                deniedPrepare.setOrigStmt(new OriginStatement(wildcardSql, 0));
                StmtExecutor deniedExecutor = new StmtExecutor(ctx, deniedPrepare);
                ErrorReportException denied = assertThrows(ErrorReportException.class,
                        () -> Deencapsulation.invoke(deniedExecutor, "generateExecPlan"));
                Assertions.assertTrue(denied.getMessage().contains("Access denied"), denied.getMessage());

                rowPolicyEnabled.set(false);
                deniedColumn.set("event_id");
                String countSql = "select count(*) from prepared_rls where ? > 0";
                PrepareStmt countPrepare = (PrepareStmt) SqlParser.parse(
                        countSql, ctx.getSessionVariable()).get(0);
                countPrepare.setName("binary_count_denied_stmt");
                countPrepare.setOrigStmt(new OriginStatement(countSql, 0));
                StmtExecutor countExecutor = new StmtExecutor(ctx, countPrepare);
                ErrorReportException countDenied = assertThrows(ErrorReportException.class,
                        () -> Deencapsulation.invoke(countExecutor, "generateExecPlan"));
                Assertions.assertTrue(countDenied.getMessage().contains("COLUMN event_id"),
                        countDenied.getMessage());
                Assertions.assertTrue(checkedColumns.contains("event_id"), checkedColumns.toString());
            }
        } finally {
            accessControlProvider.catalogToAccessControl.put(
                    InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, originalAccessControl);
            ctx.setCommand(originalCommand);
            ctx.removePreparedStmt(prepareStmt.getName());
            ctx.removePreparedStmt("binary_row_policy_denied_stmt");
            ctx.removePreparedStmt("binary_count_denied_stmt");
            ctx.getUserVariables().remove("app_channel_id");
        }
    }

    @Test
    public void testBinaryPrepareSelfJoinAuthorizesFullSchema() throws Exception {
        String sql = "select a.event_id from prepared_rls a join prepared_rls b " +
                "on a.event_id = b.event_order where ? > 0";
        PrepareStmt prepareStmt = (PrepareStmt) SqlParser.parse(sql, ctx.getSessionVariable()).get(0);
        prepareStmt.setName("binary_self_join_stmt");
        prepareStmt.setOrigStmt(new OriginStatement(sql, 0));
        AccessControlProvider accessControlProvider = Authorizer.getInstance();
        AccessController originalAccessControl = accessControlProvider.catalogToAccessControl.get(
                InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME);
        Set<String> checkedColumns = new HashSet<>();
        ExternalAccessController testAccessControl = new ExternalAccessController() {
            @Override
            public void checkColumnAction(ConnectContext ignoredContext, TableName ignoredTable,
                                          String column, PrivilegeType ignoredPrivilege)
                    throws AccessDeniedException {
                checkedColumns.add(column);
                if (column.equals("channel_id")) {
                    throw new AccessDeniedException();
                }
            }
        };
        MysqlCommand originalCommand = ctx.getCommand();
        try {
            accessControlProvider.catalogToAccessControl.put(
                    InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, testAccessControl);
            Assertions.assertSame(testAccessControl, accessControlProvider.getAccessControlOrDefault(
                    InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, ctx));
            ctx.setCommand(MysqlCommand.COM_STMT_PREPARE);

            StmtExecutor executor = new StmtExecutor(ctx, prepareStmt);
            ErrorReportException denied = assertThrows(ErrorReportException.class,
                    () -> Deencapsulation.invoke(executor, "generateExecPlan"));
            Assertions.assertTrue(denied.getMessage().contains("COLUMN channel_id"), denied.getMessage());
            Assertions.assertTrue(checkedColumns.contains("channel_id"), checkedColumns.toString());
        } finally {
            accessControlProvider.catalogToAccessControl.put(
                    InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, originalAccessControl);
            ctx.setCommand(originalCommand);
            ctx.removePreparedStmt(prepareStmt.getName());
        }
    }

    @Test
    public void testCachedPreparedPlanIsInvalidatedWhenPolicyAppears() throws Exception {
        String name = "policy_added_after_cache_stmt";
        PrepareStmt metadataStmt = (PrepareStmt) SqlParser.parse(
                "PREPARE " + name + " FROM 'select c0 from prepare_stmt where c0 = ?'",
                ctx.getSessionVariable()).get(0);
        PrepareStmtContext prepareContext = new PrepareStmtContext(metadataStmt, ctx, null);
        ctx.putPreparedStmt(name, prepareContext);
        AtomicBoolean policyEnabled = new AtomicBoolean(false);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.getColumnMaskingPolicy(
                            Mockito.any(), Mockito.any(), Mockito.any()))
                    .thenReturn(Map.of());
            authorizer.when(() -> Authorizer.getRowAccessPolicy(Mockito.any(), Mockito.any()))
                    .thenAnswer(invocation -> policyEnabled.get() ? new BoolLiteral(false) : null);

            GeneratedPreparedPlan firstPlan = generatePreparedPlan(name, new StringLiteral("first"));
            Assertions.assertTrue(prepareContext.isCached());

            policyEnabled.set(true);
            GeneratedPreparedPlan secondPlan = generatePreparedPlan(name, new StringLiteral("second"));
            String secondSql = AstToSQLBuilder.toSQL(secondPlan.executor.getParsedStmt());

            Assertions.assertNotSame(firstPlan.executor.getParsedStmt(), secondPlan.executor.getParsedStmt());
            Assertions.assertTrue(secondSql.contains("WHERE FALSE"), secondSql);
            Assertions.assertTrue(logicalPlan(secondPlan.execPlan).toLowerCase().contains("false"));
            Assertions.assertFalse(prepareContext.isCached());
        } finally {
            ctx.removePreparedStmt(name);
        }
    }

    @Test
    public void testPreparedPointQueryWithScalarSubqueryIsNotCached() throws Exception {
        String name = "nested_prepared_stmt";
        PrepareStmt metadataStmt = (PrepareStmt) SqlParser.parse(
                "PREPARE " + name + " FROM 'select (select max(c1) from prepare_stmt) "
                        + "from prepare_stmt where c0 = ?'",
                ctx.getSessionVariable()).get(0);
        PrepareStmtContext prepareContext = new PrepareStmtContext(metadataStmt, ctx, null);
        ctx.putPreparedStmt(name, prepareContext);
        try {
            generatePreparedPlan(name, new StringLiteral("first"));
            Assertions.assertFalse(prepareContext.isCached(),
                    "The point-query cache cannot safely replan scans inside a scalar subquery");
        } finally {
            ctx.removePreparedStmt(name);
        }
    }

    private GeneratedPreparedPlan generatePreparedPlan(String name, Expr value) throws Exception {
        ExecuteStmt executeStmt = new ExecuteStmt(name, List.of(value));
        executeStmt.setOrigStmt(new OriginStatement("EXECUTE " + name, 0));
        StmtExecutor executor = new StmtExecutor(ctx, executeStmt);
        ExecPlan execPlan = Deencapsulation.invoke(executor, "generateExecPlan");
        return new GeneratedPreparedPlan(executor, execPlan);
    }

    private static String logicalPlan(ExecPlan execPlan) {
        return LogicalPlanPrinter.print(execPlan.getLogicalPlan().getRoot(), true, true);
    }

    private static class GeneratedPreparedPlan {
        private final StmtExecutor executor;
        private final ExecPlan execPlan;

        private GeneratedPreparedPlan(StmtExecutor executor, ExecPlan execPlan) {
            this.executor = executor;
            this.execPlan = execPlan;
        }
    }

    @Test
    public void testPrepareStatementParser() {
        String sql = "PREPARE stmt1 FROM insert into demo.prepare_stmt values (?, ?, ?, ?);";
        Exception e = assertThrows(AnalysisException.class, () -> UtFrameUtils.parseStmtWithNewParser(sql, ctx));
        assertEquals("Getting analyzing error. Detail message: This command is not supported in the " +
                "prepared statement protocol yet.", e.getMessage());
    }

    @Test
    public void testPrepareStatementParserWithHavingClause() {
        String sql = "PREPARE stmt1 FROM SELECT prepare_stmt.c0 from prepare_stmt GROUP BY prepare_stmt.c0 HAVING COUNT(*) = ?";
        try {
            PrepareStmt stmt = (PrepareStmt) UtFrameUtils.parseStmtWithNewParser(sql, ctx);
        } catch (Exception e) {
            Assertions.fail("should not reach here");
        }

        sql = "PREPARE stmt1 FROM SELECT prepare_stmt.c0 from prepare_stmt GROUP BY prepare_stmt.c0 HAVING c0 > ?";
        try {
            PrepareStmt stmt = (PrepareStmt) UtFrameUtils.parseStmtWithNewParser(sql, ctx);
        } catch (Exception e) {
            Assertions.fail("should not reach here");
        }
    }

    @Test
    public void testPrepareStmtWithCte() throws Exception {
        String sql = "PREPARE stmt FROM with cte as (select * from prepare_stmt where c0 = ?) select * from cte where c1 = ?";
        PrepareStmt stmt = (PrepareStmt) UtFrameUtils.parseStmtWithNewParser(sql, ctx);
        QueryStatement queryStmt = (QueryStatement) stmt.getInnerStmt();
        Assertions.assertTrue(stmt.getParameters().get(1) ==
                ((SelectRelation) queryStmt.getQueryRelation()).getPredicate().getChild(1));

        sql = "PREPARE stmt FROM select *, ? from (with cte as " +
                "(select * from prepare_stmt where c0 = ?) select * from cte where c1 = ?) t where c2 = ?";
        stmt = (PrepareStmt) UtFrameUtils.parseStmtWithNewParser(sql, ctx);
        queryStmt = (QueryStatement) stmt.getInnerStmt();
        Assertions.assertTrue(stmt.getParameters().get(0) ==
                ((SelectRelation) queryStmt.getQueryRelation()).getSelectList().getItems().get(1).getExpr());
        Assertions.assertTrue(stmt.getParameters().get(3) ==
                ((SelectRelation) queryStmt.getQueryRelation()).getPredicate().getChild(1));
    }

}
