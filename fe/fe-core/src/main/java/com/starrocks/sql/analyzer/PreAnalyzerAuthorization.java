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
import com.starrocks.authorization.AccessDeniedException;
import com.starrocks.authorization.ObjectType;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.qe.ConnectContext;
import com.starrocks.server.CatalogMgr;
import com.starrocks.sql.ast.AlterViewStmt;
import com.starrocks.sql.ast.AstTraverser;
import com.starrocks.sql.ast.CTERelation;
import com.starrocks.sql.ast.CreateFunctionStmt;
import com.starrocks.sql.ast.CreateMaterializedViewStatement;
import com.starrocks.sql.ast.CreateMaterializedViewStmt;
import com.starrocks.sql.ast.CreateTableAsSelectStmt;
import com.starrocks.sql.ast.CreateTemporaryTableLikeStmt;
import com.starrocks.sql.ast.CreateTemporaryTableStmt;
import com.starrocks.sql.ast.CreateViewStmt;
import com.starrocks.sql.ast.DeleteStmt;
import com.starrocks.sql.ast.DmlStmt;
import com.starrocks.sql.ast.FileTableFunctionRelation;
import com.starrocks.sql.ast.InsertStmt;
import com.starrocks.sql.ast.QueryStatement;
import com.starrocks.sql.ast.SelectRelation;
import com.starrocks.sql.ast.SetOperationRelation;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.ast.SubmitTaskStmt;
import com.starrocks.sql.ast.TableRelation;
import com.starrocks.sql.ast.UpdateStmt;
import com.starrocks.sql.ast.UserVariable;
import com.starrocks.sql.ast.feedback.AddPlanAdvisorStmt;
import com.starrocks.sql.ast.feedback.PlanAdvisorStmt;
import com.starrocks.sql.ast.pipe.CreatePipeStmt;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

public final class PreAnalyzerAuthorization {
    public enum Result {
        NONE,
        FULL_STATEMENT,
        CREATE_PIPE,
        TARGET_BY_NAME
    }

    private PreAnalyzerAuthorization() {
    }

    public static Result authorizeBefore(StatementBase statement, ConnectContext session) {
        if (session.isBypassAuthorizerCheck()) {
            return Result.NONE;
        }

        checkRangerManagedQuery(statement, session);
        if (authorizeMetadataControlBefore(statement, session)) {
            return Result.NONE;
        }
        if (statement instanceof DmlStmt dmlStmt && shouldAuthorizeDmlTarget(dmlStmt)) {
            dmlStmt.getTableName().normalization(session);
            return authorizeDmlTarget(dmlStmt, session);
        }
        if (statement instanceof QueryStatement) {
            return Result.NONE;
        }
        if (statement instanceof CreateFunctionStmt createFunctionStmt) {
            createFunctionStmt.getFunctionName().analyze(session.getDatabase());
            Authorizer.check(statement, session);
            return Result.FULL_STATEMENT;
        }
        if (statement instanceof CreatePipeStmt createPipeStmt) {
            return authorizeCreatePipe(createPipeStmt, session);
        }
        if (statement instanceof SubmitTaskStmt submitTaskStmt) {
            return authorizeSubmitTask(submitTaskStmt, session);
        }
        if (statement instanceof CreateTableAsSelectStmt createTableAsSelectStmt) {
            return authorizeCreateTableAsSelect(createTableAsSelectStmt, session);
        }
        if (statement instanceof CreateViewStmt createViewStmt) {
            return authorizeCreateView(createViewStmt, session);
        }
        if (statement instanceof AlterViewStmt alterViewStmt) {
            return authorizeAlterView(alterViewStmt, session);
        }
        if (statement instanceof CreateMaterializedViewStatement createMaterializedViewStatement) {
            return authorizeCreateMaterializedView(createMaterializedViewStatement, session);
        }
        if (statement instanceof CreateMaterializedViewStmt createMaterializedViewStmt) {
            return authorizeCreateMaterializedView(createMaterializedViewStmt, session);
        }
        return Result.NONE;
    }

    public static void authorizeAfter(
            StatementBase statement, ConnectContext session, Result result) {
        switch (result) {
            case FULL_STATEMENT:
                break;
            case CREATE_PIPE:
                Authorizer.check(((CreatePipeStmt) statement).getInsertStmt(), session);
                break;
            case NONE:
            case TARGET_BY_NAME:
                Authorizer.check(statement, session);
                break;
            default:
                throw new IllegalStateException("Unknown pre-analysis authorization state: " + result);
        }
    }

    public static void authorizeUserVariableBeforeCalculation(
            UserVariable userVariable, ConnectContext session) {
        if (session == null || session.isBypassAuthorizerCheck()) {
            return;
        }
        Authorizer.checkRangerManagedExpressionBeforeAnalysis(
                userVariable.getUnevaluatedExpression(), session);
    }

    private static boolean authorizeMetadataControlBefore(
            StatementBase statement, ConnectContext session) {
        if (!(statement instanceof CreateTemporaryTableStmt)
                && !(statement instanceof CreateTemporaryTableLikeStmt)
                && !(statement instanceof PlanAdvisorStmt)) {
            return false;
        }

        Authorizer.getInstance().validateAccessControlContext(session);
        if (statement instanceof CreateTemporaryTableLikeStmt createLike) {
            checkCreateTemporaryTableTarget(createLike.getDbTbl(), session);
            checkCreateTemporaryTableSource(createLike.getExistedDbTbl(), session);
        } else if (statement instanceof CreateTemporaryTableStmt createTemporaryTable) {
            checkCreateTemporaryTableTarget(createTemporaryTable.getDbTbl(), session);
        } else if (statement instanceof AddPlanAdvisorStmt addPlanAdvisor) {
            Authorizer.checkSystemOperate(session);
            authorizePlanAdvisorQueryBefore(addPlanAdvisor.getQueryStmt(), session);
        } else {
            Authorizer.checkSystemOperate(session);
        }
        return true;
    }

    private static void checkCreateTemporaryTableTarget(
            TableName target, ConnectContext session) {
        TableName resolvedTarget = resolveTableName(target, session);
        checkDbTargetAction(resolvedTarget, PrivilegeType.CREATE_TABLE, session);
    }

    private static void checkCreateTemporaryTableSource(
            TableName source, ConnectContext session) {
        TableName resolvedSource = resolveTableName(source, session);
        Authorizer.checkSelectOnUnresolvedTableLikeObject(session, resolvedSource);
    }

    private static TableName resolveTableName(
            TableName tableName, ConnectContext session) {
        String catalog = tableName.getCatalog() == null
                ? session.getCurrentCatalog() : tableName.getCatalog();
        String db = tableName.getDb() == null
                ? session.getDatabase() : tableName.getDb();
        return new TableName(catalog, db, tableName.getTbl());
    }

    private static void authorizePlanAdvisorQueryBefore(
            QueryStatement queryStatement, ConnectContext session) {
        Authorizer.checkRangerManagedQueryBeforeAnalysis(queryStatement, session);
        new UnresolvedQueryAuthorizationVisitor(session).visit(queryStatement);
    }

    private static final class UnresolvedQueryAuthorizationVisitor
            extends AstTraverser<Void, Void> {
        private final ConnectContext session;
        private final Deque<Set<String>> cteNameStack = new ArrayDeque<>();

        private UnresolvedQueryAuthorizationVisitor(ConnectContext session) {
            this.session = session;
        }

        @Override
        public Void visitSelect(SelectRelation relation, Void context) {
            if (!relation.hasWithClause()) {
                return super.visitSelect(relation, context);
            }
            cteNameStack.push(new HashSet<>());
            try {
                return super.visitSelect(relation, context);
            } finally {
                cteNameStack.pop();
            }
        }

        @Override
        public Void visitSetOp(SetOperationRelation relation, Void context) {
            if (!relation.hasWithClause()) {
                return super.visitSetOp(relation, context);
            }
            cteNameStack.push(new HashSet<>());
            try {
                return super.visitSetOp(relation, context);
            } finally {
                cteNameStack.pop();
            }
        }

        @Override
        public Void visitCTE(CTERelation relation, Void context) {
            Void result = super.visitCTE(relation, context);
            if (!cteNameStack.isEmpty() && relation.getName() != null) {
                cteNameStack.peek().add(relation.getName());
            }
            return result;
        }

        @Override
        public Void visitTable(TableRelation relation, Void context) {
            TableName tableName = relation.getName();
            if (tableName == null || isCteReference(tableName)) {
                return null;
            }
            Authorizer.checkSelectOnUnresolvedTableLikeObject(
                    session, resolveTableName(tableName, session));
            return null;
        }

        private boolean isCteReference(TableName tableName) {
            if (!isEmpty(tableName.getCatalog()) || !isEmpty(tableName.getDb())) {
                return false;
            }
            for (Set<String> names : cteNameStack) {
                if (names.contains(tableName.getTbl())) {
                    return true;
                }
            }
            return false;
        }

        private boolean isEmpty(String value) {
            return value == null || value.isEmpty();
        }
    }

    public static void checkRangerManagedQuery(
            StatementBase statement, ConnectContext session) {
        if (session.isBypassAuthorizerCheck()) {
            return;
        }

        if (statement instanceof CreateViewStmt createViewStmt) {
            Authorizer.checkRangerManagedStoredDefinitionBeforeAnalysis(
                    createViewStmt.getQueryStatement(), session);
            return;
        }
        if (statement instanceof AlterViewStmt alterViewStmt) {
            if (alterViewStmt.getAlterClause() != null) {
                Authorizer.checkRangerManagedStoredDefinitionBeforeAnalysis(
                        alterViewStmt.getAlterClause().getQueryStatement(), session);
            }
            return;
        }
        if (statement instanceof CreateMaterializedViewStatement createMaterializedViewStatement) {
            Authorizer.checkRangerManagedStoredDefinitionBeforeAnalysis(
                    createMaterializedViewStatement.getQueryStatement(), session);
            return;
        }
        if (statement instanceof CreateMaterializedViewStmt createMaterializedViewStmt) {
            Authorizer.checkRangerManagedStoredDefinitionBeforeAnalysis(
                    createMaterializedViewStmt.getQueryStatement(), session);
            return;
        }

        QueryStatement queryStatement = null;
        if (statement instanceof QueryStatement) {
            queryStatement = (QueryStatement) statement;
        } else if (statement instanceof InsertStmt insertStmt) {
            if (insertStmt.useTableFunctionAsTargetTable()) {
                Authorizer.checkRangerManagedFileTableFunctionTargetBeforeAnalysis(session);
            }
            queryStatement = insertStmt.getQueryStatement();
        } else if (statement instanceof CreatePipeStmt) {
            queryStatement = ((CreatePipeStmt) statement).getInsertStmt().getQueryStatement();
        } else if (statement instanceof CreateTableAsSelectStmt) {
            queryStatement = ((CreateTableAsSelectStmt) statement).getQueryStatement();
        } else if (statement instanceof SubmitTaskStmt) {
            checkRangerManagedSubmitTaskQuery((SubmitTaskStmt) statement, session);
            return;
        }
        if (queryStatement != null) {
            Authorizer.checkRangerManagedQueryBeforeAnalysis(queryStatement, session);
        }
    }

    private static void checkRangerManagedSubmitTaskQuery(
            SubmitTaskStmt statement, ConnectContext session) {
        if (statement.getInsertStmt() != null) {
            Authorizer.checkRangerManagedQueryBeforeAnalysis(
                    statement.getInsertStmt().getQueryStatement(), session);
        } else if (statement.getCreateTableAsSelectStmt() != null) {
            Authorizer.checkRangerManagedQueryBeforeAnalysis(
                    statement.getCreateTableAsSelectStmt().getQueryStatement(), session);
        } else if (statement.getDataCacheSelectStmt() != null) {
            Authorizer.checkRangerManagedQueryBeforeAnalysis(
                    statement.getDataCacheSelectStmt().getInsertStmt().getQueryStatement(), session);
        }
    }

    private static Result authorizeCreatePipe(CreatePipeStmt statement, ConnectContext session) {
        InsertStmt insertStmt = statement.getInsertStmt();
        insertStmt.getTableName().normalization(session);
        PipeAnalyzer.analyzePipeName(statement.getPipeName(), insertStmt.getTableName().getDb());
        checkCreatePipeAction(statement, session);
        if (shouldAuthorizeTarget(insertStmt.getTableName(), session)) {
            checkDmlTargetActionByName(insertStmt, session);
        }
        return Result.CREATE_PIPE;
    }

    private static Result authorizeSubmitTask(SubmitTaskStmt statement, ConnectContext session) {
        InsertStmt insertStmt = statement.getInsertStmt();
        if (insertStmt != null) {
            insertStmt.getTableName().normalization(session);
            return authorizeDmlTarget(insertStmt, session);
        }
        if (statement.getCreateTableAsSelectStmt() != null) {
            return authorizeCreateTableAsSelect(statement.getCreateTableAsSelectStmt(), session);
        }
        return Result.NONE;
    }

    private static Result authorizeCreateTableAsSelect(
            CreateTableAsSelectStmt statement, ConnectContext session) {
        TableName tableName = statement.getCreateTableStmt().getDbTbl();
        tableName.normalization(session);
        if (shouldAuthorizeTarget(tableName, session)) {
            checkDbTargetAction(tableName, PrivilegeType.CREATE_TABLE, session);
            return Result.TARGET_BY_NAME;
        }
        return Result.NONE;
    }

    private static Result authorizeCreateView(CreateViewStmt statement, ConnectContext session) {
        TableName tableName = statement.getTableName();
        tableName.normalization(session);
        if (shouldAuthorizeTarget(tableName, session)) {
            checkDbTargetAction(tableName, PrivilegeType.CREATE_VIEW, session);
            return Result.TARGET_BY_NAME;
        }
        return Result.NONE;
    }

    private static Result authorizeAlterView(AlterViewStmt statement, ConnectContext session) {
        TableName tableName = statement.getTableName();
        tableName.normalization(session);
        if (!shouldAuthorizeTarget(tableName, session)) {
            return Result.NONE;
        }
        try {
            Authorizer.checkViewAction(session, tableName, PrivilegeType.ALTER);
        } catch (AccessDeniedException e) {
            AccessDeniedException.reportAccessDenied(
                    tableName.getCatalog(), session.getCurrentUserIdentity(), session.getCurrentRoleIds(),
                    PrivilegeType.ALTER.name(), ObjectType.VIEW.name(), tableName.getTbl());
        }
        return Result.TARGET_BY_NAME;
    }

    private static Result authorizeCreateMaterializedView(
            CreateMaterializedViewStatement statement, ConnectContext session) {
        TableName tableName = statement.getTableName();
        tableName.normalization(session);
        if (shouldAuthorizeTarget(tableName, session)) {
            checkDbTargetAction(tableName, PrivilegeType.CREATE_MATERIALIZED_VIEW, session);
            return Result.TARGET_BY_NAME;
        }
        return Result.NONE;
    }

    private static Result authorizeCreateMaterializedView(
            CreateMaterializedViewStmt statement, ConnectContext session) {
        TableName materializedViewName = statement.getTableName();
        materializedViewName.normalization(session);
        if (!CatalogMgr.isInternalCatalog(materializedViewName.getCatalog())) {
            throw new SemanticException("Synchronous materialized views only support the internal catalog");
        }
        checkDbTargetAction(materializedViewName, PrivilegeType.CREATE_MATERIALIZED_VIEW, session);

        QueryStatement queryStatement = statement.getQueryStatement();
        if (!(queryStatement.getQueryRelation() instanceof SelectRelation selectRelation) ||
                !(selectRelation.getRelation() instanceof TableRelation tableRelation) ||
                tableRelation instanceof FileTableFunctionRelation) {
            throw new SemanticException("Materialized view query statement only support direct query from table.");
        }
        TableName sourceTableName = tableRelation.getName();
        sourceTableName.normalization(session);
        if (!CatalogMgr.isInternalCatalog(sourceTableName.getCatalog())) {
            throw new SemanticException("The materialized view only support olap table.");
        }

        checkTableTargetActionByName(sourceTableName, PrivilegeType.SELECT, session);
        return Result.TARGET_BY_NAME;
    }

    private static Result authorizeDmlTarget(DmlStmt statement, ConnectContext session) {
        if (shouldAuthorizeTarget(statement.getTableName(), session)) {
            checkDmlTargetActionByName(statement, session);
            return Result.TARGET_BY_NAME;
        }
        return Result.NONE;
    }

    private static boolean shouldAuthorizeTarget(TableName tableName, ConnectContext session) {
        return CatalogMgr.isInternalCatalog(tableName.getCatalog()) || Authorizer.isRangerManagedContext(session);
    }

    private static boolean shouldAuthorizeDmlTarget(DmlStmt statement) {
        if (statement instanceof InsertStmt insertStmt) {
            return !insertStmt.isForCTAS() &&
                    !insertStmt.useTableFunctionAsTargetTable() &&
                    !insertStmt.useBlackHoleTableAsTargetTable();
        }
        return statement instanceof UpdateStmt || statement instanceof DeleteStmt;
    }

    private static void checkCreatePipeAction(CreatePipeStmt statement, ConnectContext session) {
        try {
            Authorizer.checkDbAction(
                    session, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    statement.getPipeName().getDbName(), PrivilegeType.CREATE_PIPE);
        } catch (AccessDeniedException e) {
            AccessDeniedException.reportAccessDenied(
                    InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME,
                    session.getCurrentUserIdentity(), session.getCurrentRoleIds(),
                    PrivilegeType.CREATE_PIPE.name(), ObjectType.DATABASE.name(),
                    statement.getPipeName().getDbName());
        }
    }

    private static void checkDbTargetAction(
            TableName tableName, PrivilegeType privilegeType, ConnectContext session) {
        try {
            Authorizer.checkDbAction(session, tableName.getCatalog(), tableName.getDb(), privilegeType);
        } catch (AccessDeniedException e) {
            AccessDeniedException.reportAccessDenied(
                    tableName.getCatalog(), session.getCurrentUserIdentity(), session.getCurrentRoleIds(),
                    privilegeType.name(), ObjectType.DATABASE.name(), tableName.getDb());
        }
    }

    private static void checkDmlTargetActionByName(DmlStmt statement, ConnectContext session) {
        PrivilegeType privilegeType;
        if (statement instanceof InsertStmt) {
            privilegeType = PrivilegeType.INSERT;
        } else if (statement instanceof UpdateStmt) {
            privilegeType = PrivilegeType.UPDATE;
        } else if (statement instanceof DeleteStmt) {
            privilegeType = PrivilegeType.DELETE;
        } else {
            throw new IllegalArgumentException("Unsupported DML statement: " + statement.getClass().getSimpleName());
        }

        TableName tableName = statement.getTableName();
        checkTableTargetActionByName(tableName, privilegeType, session);
    }

    private static void checkTableTargetActionByName(
            TableName tableName, PrivilegeType privilegeType, ConnectContext session) {
        try {
            Authorizer.checkTableActionByName(session, tableName, privilegeType);
        } catch (AccessDeniedException e) {
            AccessDeniedException.reportAccessDenied(
                    tableName.getCatalog(), session.getCurrentUserIdentity(), session.getCurrentRoleIds(),
                    privilegeType.name(), ObjectType.TABLE.name(), tableName.getTbl());
        }
    }
}
