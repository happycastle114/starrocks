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

import com.google.common.collect.ImmutableSet;
import com.starrocks.authentication.AuthenticationMgr;
import com.starrocks.authorization.ranger.RangerAccessController;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.common.ErrorCode;
import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.analyzer.AuthorizerStmtVisitor;
import com.starrocks.sql.analyzer.FeNameFormat;

import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AccessControlProvider {
    protected final AuthorizerStmtVisitor privilegeCheckerVisitor;
    public final Map<String, AccessController> catalogToAccessControl;
    private final AccessController rangerManagedUsersAccessControl;
    private final Set<String> rangerManagedUsers;

    public AccessControlProvider(AuthorizerStmtVisitor privilegeCheckerVisitor, AccessController accessControl) {
        this(privilegeCheckerVisitor, accessControl, null, ImmutableSet.of());
    }

    public AccessControlProvider(AuthorizerStmtVisitor privilegeCheckerVisitor, AccessController accessControl,
                                 AccessController rangerManagedUsersAccessControl, String[] rangerManagedUsers) {
        this(privilegeCheckerVisitor, accessControl, Objects.requireNonNull(rangerManagedUsersAccessControl),
                validateRangerManagedUsers(rangerManagedUsers));
    }

    private AccessControlProvider(AuthorizerStmtVisitor privilegeCheckerVisitor, AccessController accessControl,
                                  AccessController rangerManagedUsersAccessControl, Set<String> rangerManagedUsers) {
        this.privilegeCheckerVisitor = privilegeCheckerVisitor;
        this.rangerManagedUsersAccessControl = rangerManagedUsersAccessControl;
        this.rangerManagedUsers = rangerManagedUsers;

        this.catalogToAccessControl = new ConcurrentHashMap<>();
        this.catalogToAccessControl.put(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, accessControl);
    }

    public AuthorizerStmtVisitor getPrivilegeCheckerVisitor() {
        return privilegeCheckerVisitor;
    }

    public AccessController getAccessControlOrDefault(String catalogName) {
        return getAccessControlOrDefault(catalogName, ConnectContext.get());
    }

    public AccessController getAccessControlOrDefault(String catalogName, ConnectContext context) {
        if (isRangerManagedContext(context)) {
            return rangerManagedUsersAccessControl;
        }

        return getCatalogAccessControlOrDefault(catalogName);
    }

    public boolean isRangerManagedContext(ConnectContext context) {
        if (context == null) {
            return false;
        }

        String authenticatedUser = context.getQualifiedUser();
        String currentUser = context.getCurrentUserIdentity() == null ? null :
                context.getCurrentUserIdentity().getUser();
        boolean authenticatedUserManaged = isRangerManagedUser(authenticatedUser);
        boolean currentUserManaged = isRangerManagedUser(currentUser);
        if (!authenticatedUserManaged && !currentUserManaged) {
            return false;
        }

        validateAccessControlContext(context);
        return true;
    }

    public void validateAccessControlContext(ConnectContext context) {
        if (context == null) {
            return;
        }

        String authenticatedUser = context.getQualifiedUser();
        String currentUser = context.getCurrentUserIdentity() == null ? null :
                context.getCurrentUserIdentity().getUser();
        boolean authenticatedUserManaged = isRangerManagedUser(authenticatedUser);
        boolean currentUserManaged = isRangerManagedUser(currentUser);
        if (!authenticatedUserManaged && !currentUserManaged) {
            return;
        }

        if (authenticatedUser == null && currentUserManaged) {
            return;
        }

        if (!authenticatedUserManaged || !currentUserManaged || !authenticatedUser.equals(currentUser)) {
            throw ErrorReportException.report(ErrorCode.ERR_ACCESS_DENIED_FOR_EXTERNAL_ACCESS_CONTROLLER,
                    PrivilegeType.IMPERSONATE.name(), ObjectType.USER.name(),
                    currentUser == null ? "" : " " + currentUser);
        }
    }

    private boolean isRangerManagedUser(String user) {
        return user != null && rangerManagedUsers.contains(user);
    }

    private AccessController getCatalogAccessControlOrDefault(String catalogName) {
        if (catalogName == null) {
            return catalogToAccessControl.get(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME);
        }

        AccessController catalogAccessController = catalogToAccessControl.get(catalogName);
        if (catalogAccessController != null) {
            return catalogAccessController;
        } else {
            return catalogToAccessControl.get(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME);
        }
    }

    private static Set<String> validateRangerManagedUsers(String[] configuredUsers) {
        if (configuredUsers == null || configuredUsers.length == 0) {
            throw new IllegalArgumentException(
                    "ranger_managed_users must contain at least one user in hybrid_ranger_users mode");
        }

        Set<String> validatedUsers = new HashSet<>();
        for (String user : configuredUsers) {
            if (user == null || user.isEmpty()) {
                throw new IllegalArgumentException("ranger_managed_users cannot contain an empty user");
            }
            if (!user.equals(user.trim()) || user.chars().anyMatch(Character::isWhitespace)) {
                throw new IllegalArgumentException(
                        "ranger_managed_users cannot contain whitespace: " + user);
            }
            if (AuthenticationMgr.ROOT_USER.equals(user)) {
                throw new IllegalArgumentException("ranger_managed_users cannot contain root");
            }
            try {
                FeNameFormat.checkUserName(user);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("Invalid user in ranger_managed_users: " + user, e);
            }
            if (!validatedUsers.add(user)) {
                throw new IllegalArgumentException("Duplicate user in ranger_managed_users: " + user);
            }
        }
        return ImmutableSet.copyOf(validatedUsers);
    }

    public void setAccessControl(String catalog, AccessController accessControl) {
        AccessController obsoleteAccessController = catalogToAccessControl.put(catalog, accessControl);
        if (obsoleteAccessController instanceof RangerAccessController) {
            // Clean up Ranger related threads and context
            ((RangerAccessController) obsoleteAccessController).getRangerPlugin().cleanup();
        }
    }

    public void removeAccessControl(String catalog) {
        AccessController accessController = catalogToAccessControl.get(catalog);
        if (accessController == null) {
            return;
        }

        catalogToAccessControl.remove(catalog);

        if (accessController instanceof RangerAccessController) {
            // Clean up Ranger related threads and context
            ((RangerAccessController) accessController).getRangerPlugin().cleanup();
        }
    }
}
