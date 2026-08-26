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

import com.starrocks.authorization.PrivilegeType;
import com.starrocks.qe.ConnectContext;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.server.RunMode;
import com.starrocks.sql.ast.AdminAlterAutomatedSnapshotIntervalStmt;
import com.starrocks.sql.ast.AdminSetAutomatedSnapshotOffStmt;
import com.starrocks.sql.ast.AdminSetAutomatedSnapshotOnStmt;
import com.starrocks.sql.ast.StatementBase;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.List;

public class ClusterSnapshotAuthorizationTest {
    private static final String STORAGE_VOLUME = "snapshot_volume";

    @Test
    public void testSystemDenialPrecedesSnapshotStateAccess() {
        ConnectContext context = new ConnectContext();
        List<StatementBase> statements = List.of(
                new AdminSetAutomatedSnapshotOnStmt(STORAGE_VOLUME, null),
                new AdminSetAutomatedSnapshotOffStmt(),
                new AdminAlterAutomatedSnapshotIntervalStmt(null));

        for (StatementBase statement : statements) {
            try (MockedStatic<RunMode> runMode = Mockito.mockStatic(RunMode.class);
                    MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                    MockedStatic<GlobalStateMgr> globalState = Mockito.mockStatic(GlobalStateMgr.class)) {
                runMode.when(RunMode::isSharedDataMode).thenReturn(true);
                authorizer.when(() -> Authorizer.checkSystemAction(context, PrivilegeType.OPERATE))
                        .thenThrow(new SecurityException("system denied"));

                SecurityException error = Assertions.assertThrows(
                        SecurityException.class,
                        () -> ClusterSnapshotAnalyzer.analyze(statement, context));

                Assertions.assertEquals("system denied", error.getMessage());
                globalState.verifyNoInteractions();
            }
        }
    }

    @Test
    public void testStorageVolumeDenialPrecedesSnapshotStateAccess() {
        ConnectContext context = new ConnectContext();
        AdminSetAutomatedSnapshotOnStmt statement =
                new AdminSetAutomatedSnapshotOnStmt(STORAGE_VOLUME, null);

        try (MockedStatic<RunMode> runMode = Mockito.mockStatic(RunMode.class);
                MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalState = Mockito.mockStatic(GlobalStateMgr.class)) {
            runMode.when(RunMode::isSharedDataMode).thenReturn(true);
            authorizer.when(() -> Authorizer.checkStorageVolumeAction(
                            context, STORAGE_VOLUME, PrivilegeType.USAGE))
                    .thenThrow(new SecurityException("storage denied"));

            SecurityException error = Assertions.assertThrows(
                    SecurityException.class,
                    () -> ClusterSnapshotAnalyzer.analyze(statement, context));

            Assertions.assertEquals("storage denied", error.getMessage());
            authorizer.verify(() -> Authorizer.checkSystemAction(context, PrivilegeType.OPERATE));
            globalState.verifyNoInteractions();
        }
    }

    @Test
    public void testAuthorizationPrecedesSnapshotStateValidation() {
        ConnectContext context = new ConnectContext();
        AdminSetAutomatedSnapshotOnStmt statement =
                new AdminSetAutomatedSnapshotOnStmt(STORAGE_VOLUME, null);

        try (MockedStatic<RunMode> runMode = Mockito.mockStatic(RunMode.class);
                MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalState = Mockito.mockStatic(GlobalStateMgr.class)) {
            runMode.when(RunMode::isSharedDataMode).thenReturn(true);
            globalState.when(GlobalStateMgr::getCurrentState)
                    .thenThrow(new IllegalStateException("state reached"));

            IllegalStateException error = Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> ClusterSnapshotAnalyzer.analyze(statement, context));

            Assertions.assertEquals("state reached", error.getMessage());
            authorizer.verify(() -> Authorizer.checkSystemAction(context, PrivilegeType.OPERATE));
            authorizer.verify(() -> Authorizer.checkStorageVolumeAction(
                    context, STORAGE_VOLUME, PrivilegeType.USAGE));
        }
    }

    @Test
    public void testSharedNothingModeRejectsBeforeAuthorization() {
        ConnectContext context = new ConnectContext();
        AdminSetAutomatedSnapshotOnStmt statement =
                new AdminSetAutomatedSnapshotOnStmt(STORAGE_VOLUME, null);

        try (MockedStatic<RunMode> runMode = Mockito.mockStatic(RunMode.class);
                MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class);
                MockedStatic<GlobalStateMgr> globalState = Mockito.mockStatic(GlobalStateMgr.class)) {
            runMode.when(RunMode::isSharedDataMode).thenReturn(false);

            Assertions.assertThrows(
                    SemanticException.class,
                    () -> ClusterSnapshotAnalyzer.analyze(statement, context));

            authorizer.verifyNoInteractions();
            globalState.verifyNoInteractions();
        }
    }
}
