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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.starrocks.analysis.Expr;
import com.starrocks.analysis.TableName;
import com.starrocks.authorization.AccessControlProvider;
import com.starrocks.authorization.AccessController;
import com.starrocks.authorization.AccessDeniedException;
import com.starrocks.authorization.ObjectType;
import com.starrocks.authorization.PEntryObject;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.authorization.RangerManagedViewSecurity;
import com.starrocks.catalog.BasicTable;
import com.starrocks.catalog.Column;
import com.starrocks.catalog.Database;
import com.starrocks.catalog.Function;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.catalog.Table;
import com.starrocks.common.MetaNotFoundException;
import com.starrocks.common.Pair;
import com.starrocks.qe.ConnectContext;
import com.starrocks.server.CatalogMgr;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.server.WarehouseManager;
import com.starrocks.sql.ast.QueryStatement;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.ast.UserIdentity;
import com.starrocks.sql.ast.pipe.PipeName;
import com.starrocks.statistic.AnalyzeJob;
import com.starrocks.statistic.AnalyzeMgr;
import com.starrocks.statistic.AnalyzeStatus;
import com.starrocks.statistic.NativeAnalyzeJob;
import com.starrocks.warehouse.Warehouse;
import org.apache.commons.collections4.ListUtils;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class Authorizer {
    private final AccessControlProvider accessControlProvider;

    public Authorizer(AccessControlProvider accessControlProvider) {
        this.accessControlProvider = accessControlProvider;
    }

    public static AccessControlProvider getInstance() {
        return GlobalStateMgr.getCurrentState().getAuthorizer().accessControlProvider;
    }

    public static boolean isRangerManagedContext(ConnectContext context) {
        return getInstance().isRangerManagedContext(context);
    }

    public static boolean isPlannerRewriteAllowed(ConnectContext context) {
        return context.isBypassAuthorizerCheck() || !isRangerManagedContext(context);
    }

    public static void check(StatementBase statement, ConnectContext context) {
        AccessControlProvider accessControlProvider = getInstance();
        accessControlProvider.validateAccessControlContext(context);
        accessControlProvider.getPrivilegeCheckerVisitor().check(statement, context);
    }

    public static void checkRangerManagedQueryBeforeAnalysis(QueryStatement statement, ConnectContext context) {
        RangerManagedViewSecurity.checkDirectQuery(context, statement);
    }

    public static void checkRangerManagedExpressionBeforeAnalysis(Expr expression, ConnectContext context) {
        RangerManagedViewSecurity.checkDirectExpression(context, expression);
    }

    public static void checkRangerManagedFileTableFunctionTargetBeforeAnalysis(ConnectContext context) {
        RangerManagedViewSecurity.checkDirectFileTableFunctionTarget(context);
    }

    public static void checkRangerManagedStoredDefinitionBeforeAnalysis(
            QueryStatement statement, ConnectContext context) {
        RangerManagedViewSecurity.checkStoredDefinitionBeforeAnalysis(context, statement);
    }

    public static void checkSystemAction(ConnectContext context, PrivilegeType privilegeType)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkSystemAction(context, privilegeType);
    }

    public static void checkUserAction(ConnectContext context, UserIdentity impersonateUser,
                                       PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkUserAction(context, impersonateUser, privilegeType);
    }

    public static void checkCatalogAction(ConnectContext context, String catalogName,
                                          PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkCatalogAction(context, catalogName, privilegeType);
    }

    public static void checkAnyActionOnCatalog(ConnectContext context, String catalogName)
            throws AccessDeniedException {
        //Any user has an implicit usage permission on the internal catalog
        if (!CatalogMgr.isInternalCatalog(catalogName)) {
            getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                    .checkAnyActionOnCatalog(context, catalogName);
        }
    }

    public static void checkDbAction(ConnectContext context, String catalogName, String db,
                                     PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(catalogName, context)
                .checkDbAction(context, catalogName, db, privilegeType);
    }

    public static void checkAnyActionOnDb(ConnectContext context, String catalogName, String db)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(catalogName, context).checkAnyActionOnDb(context, catalogName, db);
    }

    public static void checkTableAction(ConnectContext context, String db, String table,
                                        PrivilegeType privilegeType) throws AccessDeniedException {
        TableName tableName = new TableName(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, db, table);
        Optional<Table> tableObj = GlobalStateMgr.getCurrentState().getMetadataMgr().getTable(context, tableName);
        if (tableObj.isPresent() && !tableObj.get().isTable() && privilegeType.equals(PrivilegeType.INSERT)) {
            return;
        }
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkTableAction(context,
                        new TableName(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, db, table), privilegeType);
    }

    public static void checkTableAction(ConnectContext context, String catalog, String db,
                                        String table, PrivilegeType privilegeType) throws AccessDeniedException {
        TableName tableName = new TableName(catalog, db, table);
        Optional<Table> tableObj = GlobalStateMgr.getCurrentState().getMetadataMgr().getTable(context, tableName);
        if (tableObj.isPresent() && !tableObj.get().isTable() && privilegeType.equals(PrivilegeType.INSERT)) {
            return;
        }
        getInstance().getAccessControlOrDefault(catalog, context).checkTableAction(context,
                new TableName(catalog, db, table), privilegeType);
    }

    public static void checkTableAction(ConnectContext context, TableName tableName,
                                        PrivilegeType privilegeType) throws AccessDeniedException {
        Optional<Table> table = GlobalStateMgr.getCurrentState().getMetadataMgr().getTable(context, tableName);
        if (table.isPresent() && !table.get().isTable() && privilegeType.equals(PrivilegeType.INSERT)) {
            return;
        }
        String catalog = tableName.getCatalog();
        getInstance().getAccessControlOrDefault(catalog, context)
                .checkTableAction(context, tableName, privilegeType);
    }

    public static void checkTableActionByName(ConnectContext context, TableName tableName,
                                              PrivilegeType privilegeType) throws AccessDeniedException {
        AccessControlProvider accessControlProvider = getInstance();
        accessControlProvider.validateAccessControlContext(context);
        accessControlProvider.getAccessControlOrDefault(tableName.getCatalog(), context)
                .checkTableAction(context, tableName, privilegeType);
    }

    public static void checkSelectOnUnresolvedTableLikeObject(
            ConnectContext context, TableName tableName) {
        AccessControlProvider accessControlProvider = getInstance();
        accessControlProvider.validateAccessControlContext(context);
        if (CatalogMgr.isInternalCatalog(tableName.getCatalog())) {
            Table table = getInternalTableLikeObject(context, tableName);
            if (table == null) {
                return;
            }
            checkSelectOnTableLikeObject(context, tableName, table);
            return;
        }

        try {
            accessControlProvider.getAccessControlOrDefault(tableName.getCatalog(), context)
                    .checkTableAction(context, tableName, PrivilegeType.SELECT);
        } catch (AccessDeniedException e) {
            reportSelectDenied(context, tableName);
        }
    }

    private static Table getInternalTableLikeObject(
            ConnectContext context, TableName tableName) {
        GlobalStateMgr globalState = GlobalStateMgr.getCurrentState();
        Database database = globalState.getLocalMetastore().getDb(tableName.getDb());
        if (database == null) {
            return null;
        }
        Table temporaryTable = globalState.getMetadataMgr().getTemporaryTable(
                context.getSessionId(), tableName.getCatalog(),
                database.getId(), tableName.getTbl());
        return temporaryTable != null
                ? temporaryTable
                : globalState.getLocalMetastore().getTable(tableName.getDb(), tableName.getTbl());
    }

    private static void checkSelectOnTableLikeObject(
            ConnectContext context, TableName tableName, Table table) {
        try {
            doCheckTableLikeObject(context, tableName.getDb(), table, PrivilegeType.SELECT);
        } catch (AccessDeniedException e) {
            reportSelectDenied(context, tableName);
        }
    }

    private static void reportSelectDenied(ConnectContext context, TableName tableName) {
        AccessDeniedException.reportAccessDenied(
                tableName.getCatalog(), context.getCurrentUserIdentity(),
                context.getCurrentRoleIds(),
                PrivilegeType.SELECT.name(), ObjectType.TABLE.name(), tableName.getTbl());
    }

    public static void checkAnyActionOnTable(ConnectContext context, TableName tableName)
            throws AccessDeniedException {
        String catalog = tableName.getCatalog();
        getInstance().getAccessControlOrDefault(catalog, context).checkAnyActionOnTable(context, tableName);
    }

    public static void checkColumnAction(ConnectContext context,
                                         TableName tableName, String column,
                                         PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(tableName.getCatalog(), context).checkColumnAction(context,
                tableName, column, privilegeType);
    }

    public static void checkViewAction(ConnectContext context, TableName tableName,
                                       PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkViewAction(context, tableName, privilegeType);
    }

    public static void checkAnyActionOnView(ConnectContext context, TableName tableName)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkAnyActionOnView(context, tableName);
    }

    public static void checkMaterializedViewAction(ConnectContext context, TableName tableName,
                                                   PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkMaterializedViewAction(context, tableName, privilegeType);
    }

    public static void checkAnyActionOnMaterializedView(ConnectContext context,
                                                        TableName tableName) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkAnyActionOnMaterializedView(context, tableName);
    }

    public static void checkActionOnTableLikeObject(ConnectContext context, TableName tableName,
                                                    PrivilegeType privilegeType) throws AccessDeniedException {
        Optional<Table> table = GlobalStateMgr.getCurrentState().getMetadataMgr().getTable(context, tableName);
        if (table.isPresent()) {
            doCheckTableLikeObject(context, tableName.getDb(), table.get(), privilegeType);
        }
    }

    public static void checkAnyActionOnTableLikeObject(ConnectContext context, String dbName,
                                                       BasicTable tableBasicInfo) throws AccessDeniedException {
        doCheckTableLikeObject(context, dbName, tableBasicInfo, null);
    }

    private static void doCheckTableLikeObject(ConnectContext context, String dbName,
                                               BasicTable tbl, PrivilegeType privilegeType) throws AccessDeniedException {
        if (tbl == null) {
            return;
        }

        Table.TableType type = tbl.getType();
        switch (type) {
            case OLAP:
            case OLAP_EXTERNAL:
            case CLOUD_NATIVE:
            case MYSQL:
            case ELASTICSEARCH:
            case HIVE:
            case HIVE_VIEW:
            case ICEBERG:
            case ICEBERG_VIEW:
            case HUDI:
            case JDBC:
            case DELTALAKE:
            case FILE:
            case SCHEMA:
            case PAIMON:
            case ODPS:
            case KUDU:
                // `privilegeType == null` meaning we don't check specified action, just any action
                if (privilegeType == null) {
                    checkAnyActionOnTable(context, new TableName(tbl.getCatalogName(), dbName, tbl.getName()));
                } else {
                    checkTableAction(context, dbName, tbl.getName(), privilegeType);
                }
                break;
            case MATERIALIZED_VIEW:
            case CLOUD_NATIVE_MATERIALIZED_VIEW:
                // `privilegeType == null` meaning we don't check specified action, just any action
                if (privilegeType == null) {
                    checkAnyActionOnMaterializedView(context, new TableName(dbName, tbl.getName()));
                } else {
                    checkMaterializedViewAction(context, new TableName(dbName, tbl.getName()),
                            privilegeType);
                }
                break;
            case VIEW:
                // `privilegeType == null` meaning we don't check specified action, just any action
                if (privilegeType == null) {
                    checkAnyActionOnView(context, new TableName(dbName, tbl.getName()));
                } else {
                    checkViewAction(context, new TableName(dbName, tbl.getName()), privilegeType);
                }
                break;
            default:
                throw new AccessDeniedException();
        }
    }

    public static void checkActionForAnalyzeStatement(ConnectContext context, TableName tableName) {
        try {
            Authorizer.checkActionOnTableLikeObject(context, tableName, PrivilegeType.SELECT);
        } catch (AccessDeniedException e) {
            AccessDeniedException.reportAccessDenied(
                    tableName.getCatalog(),
                    context.getCurrentUserIdentity(), context.getCurrentRoleIds(),
                    PrivilegeType.SELECT.name(), ObjectType.TABLE.name(), tableName.getTbl());
        }
        Optional<Table> table = GlobalStateMgr.getCurrentState().getMetadataMgr().getTable(context, tableName);
        if (table.isPresent() && table.get().isTable()) {
            try {
                Authorizer.checkActionOnTableLikeObject(context, tableName, PrivilegeType.INSERT);
            } catch (AccessDeniedException e) {
                AccessDeniedException.reportAccessDenied(
                        tableName.getCatalog(),
                        context.getCurrentUserIdentity(), context.getCurrentRoleIds(),
                        PrivilegeType.INSERT.name(), ObjectType.TABLE.name(), tableName.getTbl());
            }
        }
    }

    public static void checkPrivilegeForKillAnalyzeStatement(ConnectContext context, long analyzeId) {
        if (hasSystemOperate(context)) {
            return;
        }
        if (analyzeId == -1) {
            checkSystemOperate(context);
            return;
        }

        AnalyzeMgr analyzeMgr = GlobalStateMgr.getCurrentState().getAnalyzeMgr();
        AnalyzeStatus analyzeStatus = analyzeMgr.getAnalyzeStatus(analyzeId);
        if (analyzeStatus != null) {
            try {
                checkPrivilegeForAnalyzeTarget(context, new TableName(
                        analyzeStatus.getCatalogName(), analyzeStatus.getDbName(), analyzeStatus.getTableName()));
                return;
            } catch (MetaNotFoundException e) {
                checkSystemOperate(context);
                return;
            }
        }

        checkPrivilegeForAnalyzeJob(context, analyzeMgr.getAnalyzeJob(analyzeId));
    }

    public static void checkPrivilegeForDropAnalyzeJobStatement(ConnectContext context, long analyzeId) {
        if (hasSystemOperate(context)) {
            return;
        }
        if (analyzeId == -1) {
            checkSystemOperate(context);
            return;
        }

        AnalyzeJob analyzeJob = GlobalStateMgr.getCurrentState().getAnalyzeMgr().getAnalyzeJob(analyzeId);
        checkPrivilegeForAnalyzeJob(context, analyzeJob);
    }

    private static void checkPrivilegeForAnalyzeJob(ConnectContext context, AnalyzeJob analyzeJob) {
        if (analyzeJob == null) {
            checkSystemOperate(context);
            return;
        }
        if (analyzeJob.isAnalyzeAllDb() || analyzeJob.isAnalyzeAllTable()) {
            checkSystemOperate(context);
            return;
        }

        try {
            if (analyzeJob.isNative()) {
                NativeAnalyzeJob nativeAnalyzeJob = (NativeAnalyzeJob) analyzeJob;
                Set<TableName> tableNames = AnalyzerUtils.getAllTableNamesForAnalyzeJobStmt(
                        nativeAnalyzeJob.getDbId(), nativeAnalyzeJob.getTableId());
                if (tableNames.isEmpty()) {
                    checkSystemOperate(context);
                    return;
                }
                tableNames.forEach(tableName -> checkPrivilegeForAnalyzeTarget(context, tableName));
            } else {
                checkPrivilegeForAnalyzeTarget(context, new TableName(
                        analyzeJob.getCatalogName(), analyzeJob.getDbName(), analyzeJob.getTableName()));
            }
        } catch (MetaNotFoundException e) {
            checkSystemOperate(context);
        }
    }

    private static void checkPrivilegeForAnalyzeTarget(ConnectContext context, TableName tableName) {
        if (GlobalStateMgr.getCurrentState().getMetadataMgr().getTable(context, tableName).isEmpty()) {
            checkSystemOperate(context);
            return;
        }
        checkActionForAnalyzeStatement(context, tableName);
    }

    public static boolean hasSystemOperate(ConnectContext context) {
        if (context.isBypassAuthorizerCheck()) {
            return true;
        }
        getInstance().validateAccessControlContext(context);
        try {
            checkSystemAction(context, PrivilegeType.OPERATE);
            return true;
        } catch (AccessDeniedException e) {
            return false;
        }
    }

    public static void checkSystemOperate(ConnectContext context) {
        if (context.isBypassAuthorizerCheck()) {
            return;
        }
        getInstance().validateAccessControlContext(context);
        try {
            checkSystemAction(context, PrivilegeType.OPERATE);
        } catch (AccessDeniedException e) {
            AccessDeniedException.reportAccessDenied(
                    InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    context.getCurrentUserIdentity(), context.getCurrentRoleIds(),
                    PrivilegeType.OPERATE.name(), ObjectType.SYSTEM.name(), null);
        }
    }

    public static void checkFunctionAction(ConnectContext context, Database database,
                                           Function function, PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkFunctionAction(context, database, function, privilegeType);
    }

    public static void checkAnyActionOnFunction(ConnectContext context, String database, Function function)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkAnyActionOnFunction(context, database, function);
    }

    public static void checkGlobalFunctionAction(ConnectContext context, Function function,
                                                 PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkGlobalFunctionAction(context, function, privilegeType);
    }

    public static void checkAnyActionOnGlobalFunction(ConnectContext context, Function function)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkAnyActionOnGlobalFunction(context, function);
    }

    public static void checkActionInDb(ConnectContext context, String db, PrivilegeType privilegeType)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkActionInDb(context, db, privilegeType);
    }

    /**
     * A lambda function that throws AccessDeniedException
     */
    @FunctionalInterface
    public interface AccessControlChecker {
        void check() throws AccessDeniedException;
    }

    /**
     * Check whether current user has any privilege action on the db or objects(table/view/mv) in the db.
     * Currently, it's used by `show databases` or `use database`.
     */
    public static void checkAnyActionOnOrInDb(ConnectContext context, String catalogName, String db)
            throws AccessDeniedException {
        Preconditions.checkNotNull(db, "db should not null");
        AccessController controller = getInstance().getAccessControlOrDefault(catalogName, context);

        List<AccessControlChecker> basicCheckers = ImmutableList.of(
                () -> controller.checkAnyActionOnDb(context, catalogName, db),
                () -> controller.checkAnyActionOnAnyTable(context, catalogName, db)
        );
        List<AccessControlChecker> extraCheckers = ImmutableList.of(
                () -> controller.checkAnyActionOnAnyView(context, db),
                () -> controller.checkAnyActionOnAnyMaterializedView(context, db),
                () -> controller.checkAnyActionOnAnyFunction(context, db),
                () -> controller.checkAnyActionOnPipe(context, new PipeName("*", "*"))
        );
        List<AccessControlChecker> appliedCheckers = CatalogMgr.isInternalCatalog(catalogName) ?
                ListUtils.union(basicCheckers, extraCheckers) : basicCheckers;

        AccessDeniedException lastExcepton = null;
        for (AccessControlChecker checker : appliedCheckers) {
            try {
                checker.check();
                return;
            } catch (AccessDeniedException e) {
                lastExcepton = e;
            }
        }
        if (lastExcepton != null) {
            throw lastExcepton;
        }
    }

    public static void checkResourceAction(ConnectContext context, String name,
                                           PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkResourceAction(context, name, privilegeType);
    }

    public static void checkAnyActionOnResource(ConnectContext context, String name)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkAnyActionOnResource(context, name);
    }

    public static void checkResourceGroupAction(ConnectContext context, String name,
                                                PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkResourceGroupAction(context, name, privilegeType);
    }

    public static void checkPipeAction(ConnectContext context, PipeName name,
                                       PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkPipeAction(context, name, privilegeType);
    }

    public static void checkAnyActionOnPipe(ConnectContext context, PipeName name)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkAnyActionOnPipe(context, name);
    }

    public static void checkStorageVolumeAction(ConnectContext context, String storageVolume,
                                                PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkStorageVolumeAction(context, storageVolume, privilegeType);
    }

    public static void checkAnyActionOnStorageVolume(ConnectContext context, String storageVolume)
            throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkAnyActionOnStorageVolume(context, storageVolume);
    }

    public static void withGrantOption(ConnectContext context, ObjectType type, List<PrivilegeType> wants,
                                       List<PEntryObject> objects) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context).
                withGrantOption(context, type, wants, objects);
    }

    public static Map<String, Expr> getColumnMaskingPolicy(ConnectContext currentUser, TableName tableName,
                                                           List<Column> columns) {
        String catalog = tableName.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : tableName.getCatalog();
        return getInstance().getAccessControlOrDefault(catalog, currentUser)
                .getColumnMaskingPolicy(currentUser, tableName, columns);
    }

    public static Expr getRowAccessPolicy(ConnectContext currentUser, TableName tableName) {
        String catalog = tableName.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : tableName.getCatalog();
        return getInstance().getAccessControlOrDefault(catalog, currentUser).getRowAccessPolicy(currentUser, tableName);
    }

    /**
     * check privilege for `show tablet` statement
     * if current user has 'OPERATE' privilege, it will result all the result
     * otherwise it will only return to the user on which it has any privilege on the corresponding table
     *
     * @return `Pair.first` means that whether user can see this tablet, `Pair.second` means
     * whether we need to hide the ip and port in the returned result
     */
    public static Pair<Boolean, Boolean> checkPrivForShowTablet(ConnectContext context, String dbName, Table table) {
        UserIdentity currentUser = context.getCurrentUserIdentity();
        // if user has 'OPERATE' privilege, can see this tablet, for backward compatibility
        try {
            Authorizer.checkSystemAction(context, PrivilegeType.OPERATE);
            return new Pair<>(true, false);
        } catch (AccessDeniedException ae) {
            try {
                Authorizer.checkAnyActionOnTableLikeObject(context, dbName, table);
                return new Pair<>(true, true);
            } catch (AccessDeniedException e) {
                return new Pair<>(false, true);
            }
        }
    }

    public static void checkWarehouseAction(ConnectContext context, String name,
                                            PrivilegeType privilegeType) throws AccessDeniedException {
        getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                .checkWarehouseAction(context, name, privilegeType);
    }

    public static void checkAnyActionOnWarehouse(ConnectContext context, String name)
            throws AccessDeniedException {
        // Any user has an implicit usage permission on the default_warehouse
        Warehouse warehouse = GlobalStateMgr.getCurrentState().getWarehouseMgr().getWarehouse(name);
        if (warehouse.getId() != WarehouseManager.DEFAULT_WAREHOUSE_ID) {
            getInstance().getAccessControlOrDefault(InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME, context)
                    .checkAnyActionOnWarehouse(context, name);
        }
    }
}
