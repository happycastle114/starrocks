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

import com.starrocks.alter.AlterJobV2;
import com.starrocks.alter.MaterializedViewHandler;
import com.starrocks.alter.RollupJobV2;
import com.starrocks.analysis.TableName;
import com.starrocks.authorization.AccessController;
import com.starrocks.authorization.AuthorizationMgr;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.catalog.Database;
import com.starrocks.catalog.DictionaryMgr;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.catalog.OlapTable;
import com.starrocks.common.DdlException;
import com.starrocks.common.ErrorReportException;
import com.starrocks.common.FeConstants;
import com.starrocks.failpoint.FailPoint;
import com.starrocks.failpoint.FailPointExecutor;
import com.starrocks.persist.gson.GsonUtils;
import com.starrocks.qe.ConnectContext;
import com.starrocks.qe.DDLStmtExecutor;
import com.starrocks.qe.ShowExecutor;
import com.starrocks.scheduler.Constants;
import com.starrocks.scheduler.Task;
import com.starrocks.scheduler.TaskManager;
import com.starrocks.scheduler.persist.TaskRunStatus;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.server.LocalMetastore;
import com.starrocks.server.MetadataMgr;
import com.starrocks.server.NodeMgr;
import com.starrocks.sql.StatementPlanner;
import com.starrocks.sql.ast.AdminSetPartitionVersionStmt;
import com.starrocks.sql.ast.CancelAlterTableStmt;
import com.starrocks.sql.ast.CancelRefreshDictionaryStmt;
import com.starrocks.sql.ast.CreateDictionaryStmt;
import com.starrocks.sql.ast.CreateUserStmt;
import com.starrocks.sql.ast.DropDictionaryStmt;
import com.starrocks.sql.ast.DropTaskStmt;
import com.starrocks.sql.ast.RefreshDictionaryStmt;
import com.starrocks.sql.ast.ShowFailPointStatement;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.ast.UpdateFailPointStatusStatement;
import com.starrocks.sql.ast.UserIdentity;
import com.starrocks.sql.parser.NodePosition;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.utframe.StarRocksAssert;
import com.starrocks.utframe.StarRocksTestBase;
import com.starrocks.utframe.UtFrameUtils;
import mockit.Invocation;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class NativeAuthorizationGuardTest extends StarRocksTestBase {
    private static final String DB = "native_authz";
    private static final String TABLE = "base_table";
    private static final String USER = "native_guard";
    private static final String EXTERNAL_CATALOG = "native_authz_external";

    private static ConnectContext context;
    private static UserIdentity testUser;
    private static AuthorizationMgr authorizationMgr;
    private static AtomicInteger failPointRegistryCalls;

    @BeforeAll
    public static void beforeAll() throws Exception {
        FeConstants.runningUnitTest = true;
        UtFrameUtils.createMinStarRocksCluster();
        context = UtFrameUtils.initCtxForNewPrivilege(UserIdentity.ROOT);
        ConnectContext.set(context);
        StarRocksAssert starRocksAssert = new StarRocksAssert(context);
        starRocksAssert.withDatabase(DB).useDatabase(DB)
                .withTable("CREATE TABLE " + DB + "." + TABLE + " ("
                        + "event_day DATE, k1 INT, v1 VARCHAR(20)) "
                        + "DUPLICATE KEY(event_day, k1) "
                        + "PARTITION BY RANGE(event_day) ("
                        + "PARTITION p1 VALUES LESS THAN ('2027-01-01')) "
                        + "DISTRIBUTED BY HASH(k1) BUCKETS 1 "
                        + "PROPERTIES('replication_num' = '1')");

        authorizationMgr = context.getGlobalStateMgr().getAuthorizationMgr();
        authorizationMgr.initBuiltinRolesAndUsers();
        CreateUserStmt createUser = (CreateUserStmt) parse("CREATE USER '" + USER + "' IDENTIFIED BY ''");
        context.getGlobalStateMgr().getAuthenticationMgr().createUser(createUser);
        testUser = createUser.getUserIdentity();
        asRoot();
    }

    @AfterEach
    public void restoreRoot() throws Exception {
        context.setCurrentCatalog(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME);
        Authorizer.getInstance().removeAccessControl(EXTERNAL_CATALOG);
        asRoot();
        revoke("OPERATE ON SYSTEM");
        revoke("SELECT ON TABLE " + DB + "." + TABLE);
        revoke("ALTER ON TABLE " + DB + "." + TABLE);
    }

    @Test
    public void testPartitionVersionDenialPreventsMutation() throws Exception {
        AdminSetPartitionVersionStmt statement = (AdminSetPartitionVersionStmt) parse(
                "ADMIN SET TABLE " + DB + "." + TABLE + " PARTITION (p1) VERSION TO 2");
        AtomicInteger mutationCalls = new AtomicInteger();
        new MockUp<LocalMetastore>() {
            @Mock
            public void setPartitionVersion(AdminSetPartitionVersionStmt ignored) {
                mutationCalls.incrementAndGet();
            }
        };

        asTestUser();
        assertAccessDenied(() -> DDLStmtExecutor.execute(statement, context), "OPERATE");
        Assertions.assertEquals(0, mutationCalls.get());

        grant("OPERATE ON SYSTEM");
        asTestUser();
        Assertions.assertDoesNotThrow(() -> DDLStmtExecutor.execute(statement, context));
        Assertions.assertEquals(1, mutationCalls.get());
    }

    @Test
    public void testDictionaryAuthorizationPrecedesResolutionAndMutation() throws Exception {
        CreateDictionaryStmt create = new CreateDictionaryStmt(
                "authz_dict", new TableName(DB, TABLE), List.of("k1"), List.of("v1"), Map.of(), NodePosition.ZERO);
        AtomicInteger metadataCalls = new AtomicInteger();
        AtomicInteger mutationCalls = new AtomicInteger();
        new MockUp<MetadataMgr>() {
            @Mock
            public Database getDb(ConnectContext ignoredContext, String ignoredCatalog, String ignoredDb) {
                metadataCalls.incrementAndGet();
                return null;
            }
        };
        new MockUp<DictionaryMgr>() {
            @Mock
            public void createDictionary(CreateDictionaryStmt ignored, String ignoredCatalog, String ignoredDb) {
                mutationCalls.incrementAndGet();
            }

            @Mock
            public void dropDictionary(String ignoredName, boolean ignoredCacheOnly, boolean ignoredReplay) {
                mutationCalls.incrementAndGet();
            }

            @Mock
            public void refreshDictionary(String ignoredName) {
                mutationCalls.incrementAndGet();
            }

            @Mock
            public void cancelRefreshDictionary(String ignoredName) {
                mutationCalls.incrementAndGet();
            }
        };

        asTestUser();
        assertAccessDenied(() -> StatementPlanner.plan(create, context), "OPERATE");
        Assertions.assertEquals(0, metadataCalls.get());
        Assertions.assertEquals(0, mutationCalls.get());

        grant("OPERATE ON SYSTEM");
        asTestUser();
        assertAccessDenied(() -> PreAnalyzerAuthorization.authorizeBefore(create, context), "SELECT");
        Assertions.assertEquals(0, metadataCalls.get());

        grant("SELECT ON TABLE " + DB + "." + TABLE);
        asTestUser();
        Assertions.assertDoesNotThrow(() -> DDLStmtExecutor.execute(create, context));
        Assertions.assertEquals(1, mutationCalls.get());

        for (StatementBase lifecycle : List.of(
                new DropDictionaryStmt("authz_dict", false, NodePosition.ZERO),
                new RefreshDictionaryStmt("authz_dict", NodePosition.ZERO),
                new CancelRefreshDictionaryStmt("authz_dict", NodePosition.ZERO))) {
            Assertions.assertDoesNotThrow(() -> DDLStmtExecutor.execute(lifecycle, context));
        }
        Assertions.assertEquals(4, mutationCalls.get());
    }

    @Test
    public void testDictionaryQuotedSourceIsStructuredTableName() throws Exception {
        CreateDictionaryStmt statement = (CreateDictionaryStmt) parseSyntax(
                "CREATE DICTIONARY quoted_dict USING `native_authz`.`table.with.dot` "
                        + "(`key.with.dot` KEY, v1 VALUE)");

        Assertions.assertEquals("native_authz", statement.getQueryableObjectName().getDb());
        Assertions.assertEquals("table.with.dot", statement.getQueryableObjectName().getTbl());
        Assertions.assertEquals("table.with.dot", statement.getQueryableObject());
        Assertions.assertEquals(List.of("key.with.dot"), statement.getDictionaryKeys());
    }

    @Test
    public void testDictionaryLifecycleDenialPreventsManagerCalls() throws Exception {
        AtomicInteger mutationCalls = new AtomicInteger();
        new MockUp<DictionaryMgr>() {
            @Mock
            public void dropDictionary(String ignoredName, boolean ignoredCacheOnly, boolean ignoredReplay) {
                mutationCalls.incrementAndGet();
            }

            @Mock
            public void refreshDictionary(String ignoredName) {
                mutationCalls.incrementAndGet();
            }

            @Mock
            public void cancelRefreshDictionary(String ignoredName) {
                mutationCalls.incrementAndGet();
            }
        };

        asTestUser();
        for (StatementBase statement : List.of(
                new DropDictionaryStmt("authz_dict", false, NodePosition.ZERO),
                new RefreshDictionaryStmt("authz_dict", NodePosition.ZERO),
                new CancelRefreshDictionaryStmt("authz_dict", NodePosition.ZERO))) {
            assertAccessDenied(() -> DDLStmtExecutor.execute(statement, context), "OPERATE");
        }
        Assertions.assertEquals(0, mutationCalls.get());
    }

    @Test
    public void testDropTaskCreatorAndOperatePolicy() throws Exception {
        Task owned = task("owned", Constants.TaskSource.CTAS, testUser);
        Task other = task("other", Constants.TaskSource.CTAS, UserIdentity.ROOT);
        Task materializedView = task("mv", Constants.TaskSource.MV, testUser);
        Task pipe = task("pipe", Constants.TaskSource.PIPE, testUser);

        asTestUser();
        Assertions.assertDoesNotThrow(() -> Authorizer.checkDropTask(context, owned, false));
        assertAccessDenied(() -> Authorizer.checkDropTask(context, owned, true), "OPERATE");
        assertAccessDenied(() -> Authorizer.checkDropTask(context, other, false), "OPERATE");
        assertAccessDenied(() -> Authorizer.checkDropTask(context, materializedView, false), "OPERATE");
        assertAccessDenied(() -> Authorizer.checkDropTask(context, pipe, false), "OPERATE");

        grant("OPERATE ON SYSTEM");
        asTestUser();
        Assertions.assertDoesNotThrow(() -> Authorizer.checkDropTask(context, owned, true));
        Assertions.assertDoesNotThrow(() -> Authorizer.checkDropTask(context, other, false));
        Assertions.assertDoesNotThrow(() -> Authorizer.checkDropTask(context, materializedView, true));
        Assertions.assertDoesNotThrow(() -> Authorizer.checkDropTask(context, pipe, true));
    }

    @Test
    public void testDropTaskSinkRechecksResolvedTaskAndRetainsRunsOnDeny() throws Exception {
        TaskManager taskManager = context.getGlobalStateMgr().getTaskManager();
        Task task = task("toctou", Constants.TaskSource.CTAS, UserIdentity.ROOT);
        String taskName = task.getName();
        String queryId = "run_" + taskName;
        DropTaskStmt statement = (DropTaskStmt) parse("DROP TASK " + taskName);

        asTestUser();
        Assertions.assertDoesNotThrow(() -> Authorizer.check(statement, context));

        TaskRunStatus run = taskRun(task, queryId);
        taskManager.createTask(task, true);
        taskManager.getTaskRunHistory().addHistory(run);
        try {
            assertAccessDenied(() -> DDLStmtExecutor.execute(statement, context), "OPERATE");
            Assertions.assertSame(task, taskManager.getTask(taskName));
            Assertions.assertSame(run, taskManager.getTaskRunHistory().getTask(queryId));

            DropTaskStmt missing = (DropTaskStmt) parse("DROP TASK missing_" + taskName);
            Assertions.assertThrows(SemanticException.class, () -> DDLStmtExecutor.execute(missing, context));
            Assertions.assertDoesNotThrow(() -> DDLStmtExecutor.execute(
                    parse("DROP TASK IF EXISTS missing_" + taskName), context));
            Assertions.assertSame(task, taskManager.getTask(taskName));
        } finally {
            taskManager.dropTasks(List.of(task.getId()), true);
            taskManager.getTaskRunHistory().removeTaskByQueryId(queryId);
        }
    }

    @Test
    public void testDropTaskForceAndGeneratedSourcesRequireOperateAtSink() throws Exception {
        TaskManager taskManager = context.getGlobalStateMgr().getTaskManager();
        List<Task> tasks = List.of(
                task("owned_force", Constants.TaskSource.CTAS, testUser),
                task("owned_mv", Constants.TaskSource.MV, testUser),
                task("owned_pipe", Constants.TaskSource.PIPE, testUser));
        for (Task task : tasks) {
            taskManager.createTask(task, true);
        }

        asTestUser();
        try {
            for (Task task : tasks) {
                assertAccessDenied(
                        () -> DDLStmtExecutor.execute(parse("DROP TASK " + task.getName() + " FORCE"), context),
                        "OPERATE");
                Assertions.assertSame(task, taskManager.getTask(task.getName()));
            }

            grant("OPERATE ON SYSTEM");
            asTestUser();
            for (Task task : tasks) {
                Assertions.assertDoesNotThrow(
                        () -> DDLStmtExecutor.execute(parse("DROP TASK " + task.getName() + " FORCE"), context));
                Assertions.assertNull(taskManager.getTask(task.getName()));
            }
        } finally {
            List<Long> retained = new ArrayList<>();
            for (Task task : tasks) {
                if (taskManager.getTask(task.getName()) != null) {
                    retained.add(task.getId());
                }
            }
            taskManager.dropTasks(retained, true);
        }
    }

    @Test
    public void testLegacyTaskCreatorMigrationIsExactIdentity() {
        Task task = GsonUtils.GSON.fromJson("{\"createUser\":\"legacy_creator\"}", Task.class);

        Assertions.assertEquals(new UserIdentity("legacy_creator", "%"), task.getUserIdentity());
    }

    @Test
    public void testLegacyMaterializedViewCancellationRequiresBaseTableAlter() throws Exception {
        Database db = context.getGlobalStateMgr().getLocalMetastore().getDb(DB);
        OlapTable table = (OlapTable) context.getGlobalStateMgr().getLocalMetastore().getTable(DB, TABLE);
        MaterializedViewHandler handler = new MaterializedViewHandler();
        String materializedView = "legacy_mv_" + context.getGlobalStateMgr().getNextId();
        RollupJobV2 job = legacyMaterializedViewJob(db, table, materializedView);
        handler.addAlterJobV2(job);
        CancelAlterTableStmt statement = (CancelAlterTableStmt) parse(
                "CANCEL ALTER MATERIALIZED VIEW FROM " + DB + "." + materializedView);
        OlapTable.OlapTableState tableState = table.getState();

        new MockUp<GlobalStateMgr>() {
            @Mock
            public MaterializedViewHandler getRollupHandler() {
                return handler;
            }
        };

        Authorizer.getInstance().setAccessControl(EXTERNAL_CATALOG, new AccessController() {
            @Override
            public void checkTableAction(ConnectContext ignoredContext, TableName ignoredTable,
                                         PrivilegeType ignoredPrivilege) {
            }
        });
        context.setCurrentCatalog(EXTERNAL_CATALOG);
        asTestUser();
        assertAccessDenied(() -> Authorizer.check(statement, context), "ALTER");
        assertAccessDenied(() -> DDLStmtExecutor.execute(statement, context), "ALTER");
        Assertions.assertEquals(AlterJobV2.JobState.PENDING, job.getJobState());
        Assertions.assertEquals(tableState, table.getState());

        context.setCurrentCatalog(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME);
        grant("ALTER ON TABLE " + DB + "." + TABLE);
        context.setCurrentCatalog(EXTERNAL_CATALOG);
        asTestUser();
        Assertions.assertDoesNotThrow(() -> Authorizer.check(statement, context));
        Assertions.assertDoesNotThrow(() -> DDLStmtExecutor.execute(statement, context));
        Assertions.assertEquals(AlterJobV2.JobState.CANCELLED, job.getJobState());
    }

    @Test
    public void testLegacyMaterializedViewCancellationRejectsResolvedJobReplacement() throws Exception {
        Database db = context.getGlobalStateMgr().getLocalMetastore().getDb(DB);
        OlapTable table = (OlapTable) context.getGlobalStateMgr().getLocalMetastore().getTable(DB, TABLE);
        MaterializedViewHandler handler = new MaterializedViewHandler();
        String materializedView = "legacy_mv_replaced_" + context.getGlobalStateMgr().getNextId();
        RollupJobV2 original = legacyMaterializedViewJob(db, table, materializedView);
        RollupJobV2 replacement = legacyMaterializedViewJob(db, table, materializedView);
        handler.addAlterJobV2(original);
        CancelAlterTableStmt statement = (CancelAlterTableStmt) parse(
                "CANCEL ALTER MATERIALIZED VIEW FROM " + DB + "." + materializedView);
        AtomicInteger authorizationCalls = new AtomicInteger();

        grant("ALTER ON TABLE " + DB + "." + TABLE);
        asTestUser();
        new MockUp<Authorizer>() {
            @Mock
            public void checkTableAlter(Invocation invocation, ConnectContext ignoredContext,
                                        TableName ignoredTable) {
                if (authorizationCalls.getAndIncrement() == 0) {
                    handler.getAlterJobsV2().remove(original.getJobId());
                    handler.addAlterJobV2(replacement);
                }
                invocation.proceed();
            }
        };

        DdlException exception = Assertions.assertThrows(
                DdlException.class, () -> handler.cancelMV(statement, context));
        Assertions.assertTrue(exception.getMessage().contains("changed during authorization"),
                exception.getMessage());
        Assertions.assertEquals(AlterJobV2.JobState.PENDING, original.getJobState());
        Assertions.assertEquals(AlterJobV2.JobState.PENDING, replacement.getJobState());
    }

    @Test
    public void testFailPointDenialPrecedesRegistryAndBackendDiscovery() throws Exception {
        failPointRegistryCalls = new AtomicInteger();
        AtomicInteger nodeMetadataCalls = new AtomicInteger();
        Thread executionThread = Thread.currentThread();
        new MockUp<FailPoint>() {
            @Mock
            public static boolean isEnabled() {
                failPointRegistryCalls.incrementAndGet();
                return true;
            }
        };
        new MockUp<GlobalStateMgr>() {
            @Mock
            public NodeMgr getNodeMgr(Invocation invocation) {
                if (Thread.currentThread() == executionThread) {
                    nodeMetadataCalls.incrementAndGet();
                }
                return invocation.proceed();
            }
        };

        UpdateFailPointStatusStatement update = (UpdateFailPointStatusStatement) parse(
                "ADMIN ENABLE FAILPOINT 'native_authz_guard' ON FRONTEND");
        ShowFailPointStatement show = (ShowFailPointStatement) parse("SHOW FAILPOINTS");
        asTestUser();
        assertAccessDenied(() -> new FailPointExecutor(update, context).execute(), "OPERATE");
        assertAccessDenied(() -> ShowExecutor.execute(show, context), "OPERATE");
        Assertions.assertEquals(0, failPointRegistryCalls.get());
        Assertions.assertEquals(0, nodeMetadataCalls.get());

        grant("OPERATE ON SYSTEM");
        asTestUser();
        Assertions.assertDoesNotThrow(() -> Authorizer.check(update, context));
        Assertions.assertDoesNotThrow(() -> Authorizer.check(show, context));
    }

    private static Task task(String suffix, Constants.TaskSource source, UserIdentity creator) {
        Task task = new Task("native_authz_" + suffix + "_" + context.getGlobalStateMgr().getNextId());
        task.setId(context.getGlobalStateMgr().getNextId());
        task.setDbName(DB);
        task.setDefinition("SELECT 1");
        task.setSource(source);
        task.setUserIdentity(creator);
        return task;
    }

    private static RollupJobV2 legacyMaterializedViewJob(Database db, OlapTable table, String materializedView) {
        return new RollupJobV2(
                context.getGlobalStateMgr().getNextId(), db.getId(), table.getId(), table.getName(), 3_600_000,
                table.getBaseIndexId(), context.getGlobalStateMgr().getNextId(), table.getName(), materializedView,
                1, null, null, 1, 1, null, (short) 0, null, null, false);
    }

    private static TaskRunStatus taskRun(Task task, String queryId) {
        TaskRunStatus status = new TaskRunStatus();
        status.setTaskId(task.getId());
        status.setTaskName(task.getName());
        status.setQueryId(queryId);
        status.setCreateTime(System.currentTimeMillis());
        status.setState(Constants.TaskRunState.PENDING);
        return status;
    }

    private static StatementBase parse(String sql) throws Exception {
        return UtFrameUtils.parseStmtWithNewParser(sql, context);
    }

    private static StatementBase parseSyntax(String sql) {
        return SqlParser.parse(sql, context.getSessionVariable()).get(0);
    }

    private static void asRoot() throws Exception {
        setIdentity(UserIdentity.ROOT);
    }

    private static void asTestUser() throws Exception {
        setIdentity(testUser);
    }

    private static void setIdentity(UserIdentity identity) throws Exception {
        context.setCurrentUserIdentity(identity);
        context.setCurrentRoleIds(authorizationMgr.getRoleIdsByUser(identity));
        context.setQualifiedUser(identity.getUser());
        ConnectContext.set(context);
    }

    private static void grant(String privilege) throws Exception {
        asRoot();
        DDLStmtExecutor.execute(parse("GRANT " + privilege + " TO " + USER), context);
    }

    private static void revoke(String privilege) throws Exception {
        try {
            DDLStmtExecutor.execute(parse("REVOKE " + privilege + " FROM " + USER), context);
        } catch (ErrorReportException ignored) {
        }
    }

    private static void assertAccessDenied(Executable executable, String privilege) {
        ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class, executable);
        Assertions.assertTrue(exception.getMessage().contains(privilege), exception.getMessage());
    }
}
