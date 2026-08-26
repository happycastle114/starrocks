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

import com.starrocks.analysis.TableName;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.catalog.Table;
import com.starrocks.common.jmockit.Deencapsulation;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.server.MetadataMgr;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.ast.DropAnalyzeJobStmt;
import com.starrocks.sql.ast.KillAnalyzeStmt;
import com.starrocks.statistic.AnalyzeJob;
import com.starrocks.statistic.AnalyzeMgr;
import com.starrocks.statistic.NativeAnalyzeJob;
import com.starrocks.statistic.StatsConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

public class AnalyzeAuthorizationTest {
    @Test
    public void testKillAllDenialDoesNotReachAnalyzeManager() {
        ConnectContext context = new ConnectContext();
        StmtExecutor executor = new StmtExecutor(context, new KillAnalyzeStmt(-1));

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            authorizer.when(() -> Authorizer.checkPrivilegeForKillAnalyzeStatement(context, -1))
                    .thenThrow(new SecurityException("denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> Deencapsulation.invoke(executor, "handleKillAnalyzeStmt"));
            globalStateMgr.verifyNoInteractions();
        }
    }

    @Test
    public void testDropAllDenialDoesNotReachAnalyzeManager() {
        ConnectContext context = new ConnectContext();
        GlobalStateMgr state = Mockito.mock(GlobalStateMgr.class);
        context.setGlobalStateMgr(state);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.checkPrivilegeForDropAnalyzeJobStatement(context, -1))
                    .thenThrow(new SecurityException("denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> new DDLStmtExecutor.StmtExecutorVisitor()
                            .visitDropAnalyzeStatement(new DropAnalyzeJobStmt(-1), context));
            Mockito.verifyNoInteractions(state);
        }
    }

    @Test
    public void testAuthorizedMutationsUseOnlyRequestedAnalyzeOperation() {
        ConnectContext context = new ConnectContext();
        GlobalStateMgr state = Mockito.mock(GlobalStateMgr.class);
        AnalyzeMgr analyzeMgr = Mockito.mock(AnalyzeMgr.class);
        context.setGlobalStateMgr(state);
        Mockito.when(state.getAnalyzeMgr()).thenReturn(analyzeMgr);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            globalStateMgr.when(GlobalStateMgr::getCurrentState).thenReturn(state);

            Deencapsulation.invoke(
                    new StmtExecutor(context, new KillAnalyzeStmt(-1)),
                    "handleKillAnalyzeStmt");
            new DDLStmtExecutor.StmtExecutorVisitor()
                    .visitDropAnalyzeStatement(new DropAnalyzeJobStmt(7), context);

            authorizer.verify(() -> Authorizer.checkPrivilegeForKillAnalyzeStatement(context, -1));
            authorizer.verify(
                    () -> Authorizer.checkPrivilegeForDropAnalyzeJobStatement(context, 7));
            Mockito.verify(analyzeMgr).killAllPendingTasks();
            Mockito.verify(analyzeMgr).removeAnalyzeJob(7);
            Mockito.verifyNoMoreInteractions(analyzeMgr);
        }
    }

    @Test
    public void testSingleJobRetainsTargetAnalyzePrivilegePath() throws Exception {
        ConnectContext context = new ConnectContext();
        GlobalStateMgr state = Mockito.mock(GlobalStateMgr.class);
        MetadataMgr metadataMgr = Mockito.mock(MetadataMgr.class);
        Table table = Mockito.mock(Table.class);
        AnalyzeMgr analyzeMgr = Mockito.mock(AnalyzeMgr.class);
        AnalyzeJob analyzeJob = Mockito.mock(AnalyzeJob.class);
        AtomicReference<TableName> checkedTarget = new AtomicReference<>();
        Mockito.when(state.getAnalyzeMgr()).thenReturn(analyzeMgr);
        Mockito.when(state.getMetadataMgr()).thenReturn(metadataMgr);
        Mockito.when(metadataMgr.getTable(Mockito.eq(context), Mockito.any(TableName.class)))
                .thenReturn(Optional.of(table));
        Mockito.when(analyzeMgr.getAnalyzeJob(7)).thenReturn(analyzeJob);
        Mockito.when(analyzeJob.isNative()).thenReturn(false);
        Mockito.when(analyzeJob.getCatalogName()).thenReturn("external_catalog");
        Mockito.when(analyzeJob.getDbName()).thenReturn("db");
        Mockito.when(analyzeJob.getTableName()).thenReturn("tbl");

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(
                Authorizer.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            authorizer.when(() -> Authorizer.hasSystemOperate(context)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkActionForAnalyzeStatement(
                            Mockito.eq(context), Mockito.any(TableName.class)))
                    .thenAnswer(invocation -> {
                        checkedTarget.set(invocation.getArgument(1));
                        return null;
                    });
            globalStateMgr.when(GlobalStateMgr::getCurrentState).thenReturn(state);

            Authorizer.checkPrivilegeForDropAnalyzeJobStatement(context, 7);

            Assertions.assertEquals("external_catalog", checkedTarget.get().getCatalog());
            Assertions.assertEquals("db", checkedTarget.get().getDb());
            Assertions.assertEquals("tbl", checkedTarget.get().getTbl());
            Mockito.verify(analyzeMgr).getAnalyzeJob(7);
            Mockito.verifyNoMoreInteractions(analyzeMgr);
        }
    }

    @Test
    public void testOperateBypassesSingleJobMetadataLookup() {
        ConnectContext context = new ConnectContext();

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(
                Authorizer.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            authorizer.when(() -> Authorizer.hasSystemOperate(context)).thenReturn(true);
            globalStateMgr.clearInvocations();

            Authorizer.checkPrivilegeForKillAnalyzeStatement(context, 7);
            Authorizer.checkPrivilegeForDropAnalyzeJobStatement(context, 7);

            globalStateMgr.verifyNoInteractions();
        }
    }

    @Test
    public void testAllAndUnknownIdsRequireOperateWithMinimalMetadataLookup() {
        ConnectContext context = new ConnectContext();

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(
                Authorizer.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            authorizer.when(() -> Authorizer.hasSystemOperate(context)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkSystemOperate(context))
                    .thenThrow(new SecurityException("denied"));
            globalStateMgr.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> Authorizer.checkPrivilegeForKillAnalyzeStatement(context, -1));
            globalStateMgr.verifyNoInteractions();
        }

        GlobalStateMgr state = Mockito.mock(GlobalStateMgr.class);
        AnalyzeMgr analyzeMgr = Mockito.mock(AnalyzeMgr.class);
        Mockito.when(state.getAnalyzeMgr()).thenReturn(analyzeMgr);
        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(
                Authorizer.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            authorizer.when(() -> Authorizer.hasSystemOperate(context)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkSystemOperate(context))
                    .thenThrow(new SecurityException("denied"));
            globalStateMgr.when(GlobalStateMgr::getCurrentState).thenReturn(state);
            globalStateMgr.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> Authorizer.checkPrivilegeForDropAnalyzeJobStatement(context, 404));
            Mockito.verify(analyzeMgr).getAnalyzeJob(404);
            Mockito.verifyNoMoreInteractions(analyzeMgr);
        }
    }

    @Test
    public void testGlobalNativeJobRequiresOperateWithoutEnumeratingTables() {
        ConnectContext context = new ConnectContext();
        GlobalStateMgr state = Mockito.mock(GlobalStateMgr.class);
        AnalyzeMgr analyzeMgr = Mockito.mock(AnalyzeMgr.class);
        NativeAnalyzeJob globalJob = new NativeAnalyzeJob(
                StatsConstants.DEFAULT_ALL_ID, StatsConstants.DEFAULT_ALL_ID, List.of(), List.of(),
                StatsConstants.AnalyzeType.FULL, StatsConstants.ScheduleType.SCHEDULE, Map.of(),
                StatsConstants.ScheduleStatus.PENDING, LocalDateTime.MIN);
        globalJob.setId(9);
        Mockito.when(state.getAnalyzeMgr()).thenReturn(analyzeMgr);
        Mockito.when(analyzeMgr.getAnalyzeJob(9)).thenReturn(globalJob);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(
                Authorizer.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            authorizer.when(() -> Authorizer.hasSystemOperate(context)).thenReturn(false);
            authorizer.when(() -> Authorizer.checkSystemOperate(context))
                    .thenThrow(new SecurityException("denied"));
            globalStateMgr.when(GlobalStateMgr::getCurrentState).thenReturn(state);
            globalStateMgr.clearInvocations();

            Assertions.assertThrows(SecurityException.class,
                    () -> Authorizer.checkPrivilegeForDropAnalyzeJobStatement(context, 9));
            Mockito.verify(analyzeMgr).getAnalyzeJob(9);
            Mockito.verifyNoMoreInteractions(analyzeMgr);
            globalStateMgr.verify(GlobalStateMgr::getCurrentState, Mockito.times(1));
        }
    }

    @Test
    public void testResolvedAnalyzeTargetIsAuthorizedWithoutMetadataRequery() throws Exception {
        ConnectContext context = new ConnectContext();
        GlobalStateMgr state = Mockito.mock(GlobalStateMgr.class);
        MetadataMgr metadataMgr = Mockito.mock(MetadataMgr.class);
        Table table = Mockito.mock(Table.class);
        TableName target = new TableName("external_catalog", "db", "tbl");
        List<PrivilegeType> checkedActions = new ArrayList<>();
        AtomicReference<TableName> checkedTarget = new AtomicReference<>();
        Mockito.when(state.getMetadataMgr()).thenReturn(metadataMgr);
        Mockito.when(metadataMgr.getTable(context, target))
                .thenReturn(Optional.of(table), Optional.empty());
        Mockito.when(table.getType()).thenReturn(Table.TableType.HIVE);
        Mockito.when(table.isTable()).thenReturn(true);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(
                Authorizer.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            globalStateMgr.when(GlobalStateMgr::getCurrentState).thenReturn(state);
            authorizer.when(() -> Authorizer.checkTableActionByName(
                            Mockito.same(context), Mockito.any(TableName.class),
                            Mockito.any(PrivilegeType.class)))
                    .thenAnswer(invocation -> {
                        checkedTarget.set(invocation.getArgument(1));
                        checkedActions.add(invocation.getArgument(2));
                        return null;
                    });

            Authorizer.checkActionForAnalyzeStatement(context, target);

            Assertions.assertSame(target, checkedTarget.get());
            Assertions.assertEquals(
                    List.of(PrivilegeType.SELECT, PrivilegeType.INSERT), checkedActions);
            Mockito.verify(metadataMgr).getTable(context, target);
            Mockito.verifyNoMoreInteractions(metadataMgr);
        }
    }

    @Test
    public void testMissingAnalyzeTargetRequiresOperate() {
        ConnectContext context = new ConnectContext();
        GlobalStateMgr state = Mockito.mock(GlobalStateMgr.class);
        MetadataMgr metadataMgr = Mockito.mock(MetadataMgr.class);
        TableName target = new TableName("external_catalog", "db", "missing_tbl");
        Mockito.when(state.getMetadataMgr()).thenReturn(metadataMgr);
        Mockito.when(metadataMgr.getTable(context, target)).thenReturn(Optional.empty());

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(
                Authorizer.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<GlobalStateMgr> globalStateMgr =
                        Mockito.mockStatic(GlobalStateMgr.class)) {
            globalStateMgr.when(GlobalStateMgr::getCurrentState).thenReturn(state);
            authorizer.when(() -> Authorizer.checkSystemOperate(context))
                    .thenThrow(new SecurityException("denied"));

            Assertions.assertThrows(SecurityException.class,
                    () -> Authorizer.checkActionForAnalyzeStatement(context, target));
            Mockito.verify(metadataMgr).getTable(context, target);
            Mockito.verifyNoMoreInteractions(metadataMgr);
        }
    }
}
