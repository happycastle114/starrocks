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

import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.ast.UserIdentity;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AccessControlProviderHybridTest {
    private static final String MANAGED_USER = "flight_sql_ci";

    @Test
    public void testContextAwareControllerSelection() {
        AccessController nativeController = new AccessController() { };
        AccessController rangerController = new AccessController() { };
        AccessController catalogController = new AccessController() { };
        String[] configuredUsers = {MANAGED_USER};
        AccessControlProvider provider = new AccessControlProvider(
                null, nativeController, rangerController, configuredUsers);
        configuredUsers[0] = "changed_after_startup";
        provider.setAccessControl("external", catalogController);

        ConnectContext context = context(MANAGED_USER, new UserIdentity(MANAGED_USER, "%"));
        Assertions.assertSame(rangerController, provider.getAccessControlOrDefault("external", context));

        context = context(null, new UserIdentity(MANAGED_USER, "%"));
        Assertions.assertSame(rangerController, provider.getAccessControlOrDefault("external", context));

        context = context("ordinary", new UserIdentity("ordinary", "%"));
        Assertions.assertSame(catalogController, provider.getAccessControlOrDefault("external", context));

        context = context("changed_after_startup", new UserIdentity("changed_after_startup", "%"));
        Assertions.assertSame(catalogController, provider.getAccessControlOrDefault("external", context));
    }

    @Test
    public void testManagedAndCurrentIdentityDivergenceFailsClosed() {
        AccessControlProvider provider = new AccessControlProvider(
                null, new AccessController() { }, new AccessController() { }, new String[] {MANAGED_USER});

        Assertions.assertThrows(ErrorReportException.class,
                () -> provider.getAccessControlOrDefault(null,
                        context(MANAGED_USER, new UserIdentity("ordinary", "%"))));
        Assertions.assertThrows(ErrorReportException.class,
                () -> provider.getAccessControlOrDefault(null,
                        context(MANAGED_USER, null)));
        Assertions.assertThrows(ErrorReportException.class,
                () -> provider.getAccessControlOrDefault(null,
                        context("ordinary", new UserIdentity(MANAGED_USER, "%"))));
    }

    @Test
    public void testInvalidManagedUsersRejected() {
        String[][] invalidUsers = {
                {}, {null}, {""}, {"root"}, {"{USER}"}, {"*"}, {"%"},
                {" leading"}, {"trailing "}, {"embedded user"}, {MANAGED_USER, MANAGED_USER}
        };

        for (String[] invalid : invalidUsers) {
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new AccessControlProvider(
                            null, new AccessController() { }, new AccessController() { }, invalid));
        }
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new AccessControlProvider(
                        null, new AccessController() { }, new AccessController() { }, null));
    }

    private static ConnectContext context(String authenticatedUser, UserIdentity currentUser) {
        ConnectContext context = new ConnectContext();
        context.setQualifiedUser(authenticatedUser);
        context.setCurrentUserIdentity(currentUser);
        return context;
    }
}
