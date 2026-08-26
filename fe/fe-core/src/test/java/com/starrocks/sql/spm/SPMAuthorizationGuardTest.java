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

package com.starrocks.sql.spm;

import com.starrocks.analysis.Expr;
import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.qe.ShowResultSet;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.sql.analyzer.Analyzer;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.ast.QueryStatement;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.ast.UserIdentity;
import com.starrocks.sql.ast.spm.ControlBaselinePlanStmt;
import com.starrocks.sql.ast.spm.CreateBaselinePlanStmt;
import com.starrocks.sql.ast.spm.DropBaselinePlanStmt;
import com.starrocks.sql.ast.spm.ShowBaselinePlanStmt;
import com.starrocks.sql.parser.SqlParser;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public class SPMAuthorizationGuardTest {
    private ConnectContext context;
    private CountingStorage sessionStorage;
    private CountingStorage globalStorage;

    @BeforeEach
    public void setUp() throws Exception {
        context = new ConnectContext();
        context.setQualifiedUser("spm_guard");
        context.setCurrentUserIdentity(new UserIdentity("spm_guard", "%"));
        ConnectContext.set(context);

        sessionStorage = new CountingStorage();
        globalStorage = new CountingStorage();
        Field storage = ConnectContext.class.getDeclaredField("sqlPlanStorage");
        storage.setAccessible(true);
        storage.set(context, sessionStorage);

        context.setGlobalStateMgr(GlobalStateMgr.getCurrentState());
        new MockUp<GlobalStateMgr>() {
            @Mock
            public SQLPlanStorage getSqlPlanStorage() {
                return globalStorage;
            }
        };
    }

    @Test
    public void testManagedPlanAndBindRejectFilesBeforeAnalyzer() {
        CreateBaselinePlanStmt forbiddenPlan = parseCreate(
                "CREATE BASELINE USING SELECT * FROM FILES(\"path\" = \"s3://bucket/file.parquet\")");
        CreateBaselinePlanStmt forbiddenBind = parseCreate(
                "CREATE BASELINE ON SELECT * FROM FILES(\"path\" = \"s3://bucket/file.parquet\") "
                        + "USING SELECT 1");

        try (MockedStatic<Authorizer> authorizer =
                    Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<Analyzer> analyzer = Mockito.mockStatic(Analyzer.class)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(true);
            authorizer.when(() -> Authorizer.check(
                    Mockito.any(StatementBase.class), Mockito.same(context)))
                    .thenAnswer(invocation -> null);

            assertFilesDenied(() -> new SPMPlanBuilder(context, forbiddenPlan).execute());
            analyzer.verifyNoInteractions();

            assertFilesDenied(() -> new SPMPlanBuilder(context, forbiddenBind).execute());
            analyzer.verify(
                    () -> Analyzer.analyze(Mockito.any(QueryStatement.class), Mockito.same(context)),
                    Mockito.times(1));
        }
        Assertions.assertEquals(0, sessionStorage.storeCalls);
        Assertions.assertEquals(0, globalStorage.storeCalls);
    }

    @Test
    public void testDeniedGlobalCreatePerformsNoAnalyzeOrStore() {
        CreateBaselinePlanStmt statement = parseCreate("CREATE GLOBAL BASELINE USING SELECT 1");
        SecurityException denied = new SecurityException("OPERATE denied");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<Analyzer> analyzer = Mockito.mockStatic(Analyzer.class)) {
            authorizer.when(() -> Authorizer.checkSystemOperate(context)).thenThrow(denied);
            Assertions.assertSame(denied,
                    Assertions.assertThrows(SecurityException.class, () -> SPMStmtExecutor.execute(context, statement)));
            analyzer.verifyNoInteractions();
        }
        Assertions.assertEquals(0, sessionStorage.storeCalls);
        Assertions.assertEquals(0, globalStorage.storeCalls);
    }

    @Test
    public void testSessionMutationDoesNotRequireOperateAndGlobalMutationFailsClosed() {
        BaselinePlan sessionPlan = baseline(10, false);
        sessionStorage.plans.add(sessionPlan);
        globalStorage.plans.add(baseline(10, true));
        DropBaselinePlanStmt dropSession = (DropBaselinePlanStmt) parse("DROP BASELINE 10");
        DropBaselinePlanStmt dropGlobal = (DropBaselinePlanStmt) parse("DROP BASELINE 99");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.checkSystemOperate(context))
                    .thenThrow(new SecurityException("OPERATE denied"));

            Assertions.assertDoesNotThrow(() -> SPMStmtExecutor.execute(context, dropSession));
            Assertions.assertEquals(1, sessionStorage.dropCalls);
            Assertions.assertEquals(0, globalStorage.dropCalls);
            Assertions.assertEquals(1, globalStorage.plans.size());

            Assertions.assertThrows(SecurityException.class, () -> SPMStmtExecutor.execute(context, dropGlobal));
            Assertions.assertEquals(1, sessionStorage.dropCalls);
            Assertions.assertEquals(0, globalStorage.dropCalls);
        }
    }

    @Test
    public void testSessionControlDoesNotRequireOperateAndGlobalControlFailsClosed() {
        BaselinePlan sessionPlan = baseline(20, false);
        sessionStorage.plans.add(sessionPlan);
        ControlBaselinePlanStmt controlSession = (ControlBaselinePlanStmt) parse("DISABLE BASELINE 20");
        ControlBaselinePlanStmt controlGlobal = (ControlBaselinePlanStmt) parse("DISABLE BASELINE 99");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.checkSystemOperate(context))
                    .thenThrow(new SecurityException("OPERATE denied"));

            Assertions.assertDoesNotThrow(() -> SPMStmtExecutor.execute(context, controlSession));
            Assertions.assertFalse(sessionPlan.isEnable());
            Assertions.assertEquals(1, sessionStorage.controlCalls);
            Assertions.assertEquals(0, globalStorage.controlCalls);

            Assertions.assertThrows(SecurityException.class, () -> SPMStmtExecutor.execute(context, controlGlobal));
            Assertions.assertEquals(1, sessionStorage.controlCalls);
            Assertions.assertEquals(0, globalStorage.controlCalls);
        }
    }

    @Test
    public void testShowHidesGlobalStateWithoutOperate() {
        sessionStorage.plans.add(baseline(30, false));
        globalStorage.plans.add(baseline(31, true));
        ShowBaselinePlanStmt statement = (ShowBaselinePlanStmt) parse("SHOW BASELINE");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.hasSystemOperate(context)).thenReturn(false);
            ShowResultSet sessionOnly = SPMStmtExecutor.execute(context, statement);
            Assertions.assertEquals(1, sessionOnly.getResultRows().size());
            Assertions.assertEquals(0, globalStorage.getCalls);

            authorizer.when(() -> Authorizer.hasSystemOperate(context)).thenReturn(true);
            ShowResultSet withGlobal = SPMStmtExecutor.execute(context, statement);
            Assertions.assertEquals(2, withGlobal.getResultRows().size());
            Assertions.assertEquals(1, globalStorage.getCalls);
        }
    }

    @Test
    public void testOperateAllowsGlobalDropAndControl() {
        sessionStorage.plans.add(baseline(40, false));
        sessionStorage.plans.add(baseline(41, false));
        globalStorage.plans.add(baseline(40, true));
        globalStorage.plans.add(baseline(41, true));
        DropBaselinePlanStmt drop = (DropBaselinePlanStmt) parse("DROP BASELINE 40");
        ControlBaselinePlanStmt control = (ControlBaselinePlanStmt) parse("ENABLE BASELINE 41");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.hasSystemOperate(context)).thenReturn(true);
            SPMStmtExecutor.execute(context, drop);
            SPMStmtExecutor.execute(context, control);
        }
        Assertions.assertEquals(1, sessionStorage.dropCalls);
        Assertions.assertEquals(1, sessionStorage.controlCalls);
        Assertions.assertEquals(1, globalStorage.dropCalls);
        Assertions.assertEquals(1, globalStorage.controlCalls);
    }

    @Test
    public void testBypassPreservesInternalSpmAnalysisAndShow() {
        context.setBypassAuthorizerCheck(true);
        context.getSessionVariable().setEnableSPMRewrite(true);
        QueryStatement query = (QueryStatement) parse("SELECT 1");
        CreateBaselinePlanStmt create = parseCreate("CREATE BASELINE USING SELECT 1");
        ShowBaselinePlanStmt show = (ShowBaselinePlanStmt) parse("SHOW BASELINE ON SELECT 1");

        try (MockedStatic<Authorizer> authorizer =
                    Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertDoesNotThrow(() -> new SPMPlanBuilder(context, create).analyze());
            Assertions.assertSame(query, new SPMPlanner(context).plan(query));
            Assertions.assertDoesNotThrow(() -> SPMStmtExecutor.execute(context, show));
            Assertions.assertDoesNotThrow(() -> Authorizer.checkSystemOperate(context));
            Assertions.assertTrue(Authorizer.hasSystemOperate(context));
            authorizer.verify(
                    () -> Authorizer.check(Mockito.any(StatementBase.class), Mockito.same(context)),
                    Mockito.never());
        }
    }

    private StatementBase parse(String sql) {
        return SqlParser.parse(sql, context.getSessionVariable()).get(0);
    }

    private CreateBaselinePlanStmt parseCreate(String sql) {
        return (CreateBaselinePlanStmt) parse(sql);
    }

    private static BaselinePlan baseline(long id, boolean global) {
        BaselinePlan plan = new BaselinePlan("SELECT 1", "SELECT 1", id, "SELECT 1", 1);
        plan.setId(id);
        plan.setGlobal(global);
        plan.setEnable(true);
        return plan;
    }

    private static void assertFilesDenied(Executable executable) {
        ErrorReportException exception = Assertions.assertThrows(ErrorReportException.class, executable);
        Assertions.assertTrue(exception.getMessage().contains("FILES"), exception.getMessage());
    }

    private static final class CountingStorage implements SQLPlanStorage {
        private final List<BaselinePlan> plans = new ArrayList<>();
        private int getCalls;
        private int storeCalls;
        private int dropCalls;
        private int controlCalls;

        @Override
        public List<BaselinePlan> getBaselines(Expr where) {
            getCalls++;
            return List.copyOf(plans);
        }

        @Override
        public void storeBaselinePlan(List<BaselinePlan> baselinePlans) {
            storeCalls++;
            plans.addAll(baselinePlans);
        }

        @Override
        public List<BaselinePlan> findBaselinePlan(String sqlDigest, long hash) {
            return List.of();
        }

        @Override
        public void dropBaselinePlan(List<Long> baselineIds) {
            dropCalls++;
            plans.removeIf(plan -> baselineIds.contains(plan.getId()));
        }

        @Override
        public void dropAllBaselinePlans() {
            plans.clear();
        }

        @Override
        public void controlBaselinePlan(boolean enable, List<Long> baselineIds) {
            controlCalls++;
            plans.stream().filter(plan -> baselineIds.contains(plan.getId())).forEach(plan -> plan.setEnable(enable));
        }
    }
}
