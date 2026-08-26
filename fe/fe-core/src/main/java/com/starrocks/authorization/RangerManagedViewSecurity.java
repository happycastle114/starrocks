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
import com.starrocks.analysis.DictQueryExpr;
import com.starrocks.analysis.FunctionCallExpr;
import com.starrocks.analysis.HintNode;
import com.starrocks.analysis.ParseNode;
import com.starrocks.analysis.TableName;
import com.starrocks.catalog.MaterializedView;
import com.starrocks.catalog.View;
import com.starrocks.common.ErrorCode;
import com.starrocks.common.ErrorReportException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.analyzer.CyclicViewException;
import com.starrocks.sql.ast.AstTraverser;
import com.starrocks.sql.ast.DictionaryGetExpr;
import com.starrocks.sql.ast.FileTableFunctionRelation;
import com.starrocks.sql.ast.QueryStatement;
import com.starrocks.sql.ast.SelectRelation;
import com.starrocks.sql.ast.TableFunctionRelation;
import com.starrocks.sql.ast.TableRelation;
import com.starrocks.sql.ast.ViewRelation;

import java.util.List;
import java.util.Locale;
import java.util.Set;

final class RangerManagedViewSecurity {
    private static final Set<String> FORBIDDEN_FUNCTIONS = ImmutableSet.of(
            "FILES",
            "DICTIONARY_GET",
            "DICT_MAPPING",
            "LOOKUP_STRING",
            "GET_QUERY_PROFILE",
            "GET_QUERY_DUMP",
            "GET_QUERY_DUMP_FROM_QUERY_ID",
            "LIST_ROWSETS",
            "HOST_NAME",
            "NATIVE_QUERY",
            "AI_QUERY",
            "SLEEP");
    private static final Set<String> FORBIDDEN_FUNCTION_PREFIXES = ImmutableSet.of("INSPECT_");
    private static final Set<String> FORBIDDEN_TABLE_HINTS = ImmutableSet.of(
            "_META_", "_BINLOG_", "_SYNC_MV_", "_USE_PK_INDEX_", "_CACHE_STATS_");
    private static final Set<String> FORBIDDEN_SCHEMAS = ImmutableSet.of(
            "INFORMATION_SCHEMA", "SYS", "_STATISTICS_");
    private static final Set<String> FORBIDDEN_CONNECTOR_METADATA_SUFFIXES = ImmutableSet.of(
            "LOGICAL_ICEBERG_METADATA",
            "REFS",
            "HISTORY",
            "METADATA_LOG_ENTRIES",
            "SNAPSHOTS",
            "MANIFESTS",
            "FILES",
            "PARTITIONS");
    private static final String VIEW_AUTHORIZATION_PATH_PREFIX = "ranger-authorization:";

    private RangerManagedViewSecurity() {
    }

    static void check(ConnectContext context, QueryStatement statement) {
        if (!Authorizer.isRangerManagedContext(context)) {
            return;
        }
        new StoredViewVisitor(context).visit(statement);
    }

    static boolean isForbiddenTableHint(String hint) {
        return hint != null && FORBIDDEN_TABLE_HINTS.contains(hint.toUpperCase(Locale.ROOT));
    }

    static boolean isForbiddenConnectorMetadataTable(String table) {
        if (table == null) {
            return false;
        }
        int separator = table.lastIndexOf('$');
        if (separator <= 0 || separator == table.length() - 1) {
            return false;
        }
        String suffix = table.substring(separator + 1).toUpperCase(Locale.ROOT);
        return FORBIDDEN_CONNECTOR_METADATA_SUFFIXES.contains(suffix);
    }

    private static boolean isForbiddenFunction(String function) {
        if (function == null) {
            return false;
        }
        String normalized = function.toUpperCase(Locale.ROOT);
        return FORBIDDEN_FUNCTIONS.contains(normalized) ||
                FORBIDDEN_FUNCTION_PREFIXES.stream().anyMatch(normalized::startsWith);
    }

    private static void denyFunction(String function) {
        deny(PrivilegeType.USAGE, ObjectType.FUNCTION, function.toUpperCase(Locale.ROOT));
    }

    private static void deny(PrivilegeType privilege, ObjectType objectType, String object) {
        throw ErrorReportException.report(
                ErrorCode.ERR_ACCESS_DENIED_FOR_EXTERNAL_ACCESS_CONTROLLER,
                privilege.name(), objectType.name(), " in Ranger-managed stored definition: " + object);
    }

    private static String authorizationPathKey(ViewRelation relation) {
        View view = relation.getView();
        if (view.isOlapView()) {
            return VIEW_AUTHORIZATION_PATH_PREFIX + "view:id:" + view.getId();
        }
        TableName name = relation.getName();
        return VIEW_AUTHORIZATION_PATH_PREFIX + "view:name:" +
                (name == null ? view.getName() : name.toString());
    }

    private static String authorizationPathKey(MaterializedView materializedView) {
        return VIEW_AUTHORIZATION_PATH_PREFIX + "materialized-view:id:" + materializedView.getId();
    }

    private static final class StoredViewVisitor extends AstTraverser<Void, Void> {
        private final ConnectContext context;

        private StoredViewVisitor(ConnectContext context) {
            this.context = context;
        }

        @Override
        public Void visitView(ViewRelation relation, Void ignored) {
            authorizeStoredQuery(
                    authorizationPathKey(relation), String.valueOf(relation.getName()), relation.getQueryStatement());
            return null;
        }

        @Override
        public Void visitTable(TableRelation relation, Void ignored) {
            if (!(relation.getTable() instanceof MaterializedView materializedView)) {
                return null;
            }

            ParseNode parseNode = materializedView.getDefineQueryParseNode();
            if (!(parseNode instanceof QueryStatement definition)) {
                deny(PrivilegeType.SELECT, ObjectType.MATERIALIZED_VIEW,
                        relation.getName() + " (definition unavailable)");
                return null;
            }
            authorizeStoredQuery(
                    authorizationPathKey(materializedView), String.valueOf(relation.getName()), definition);
            return null;
        }

        private void authorizeStoredQuery(String pathKey, String objectName, QueryStatement definition) {
            Set<String> path = context.getViewExpansionPath();
            if (!path.add(pathKey)) {
                throw new CyclicViewException(
                        "Stored relation " + objectName + " contains a cycle in its definition");
            }
            try {
                new ForbiddenDefinitionVisitor().visit(definition);
                Authorizer.check(definition, context);
            } finally {
                path.remove(pathKey);
            }
        }
    }

    private static final class ForbiddenDefinitionVisitor extends AstTraverser<Void, Void> {
        @Override
        public Void visitQueryStatement(QueryStatement statement, Void context) {
            rejectHints(statement.getAllQueryScopeHints());
            return super.visitQueryStatement(statement, context);
        }

        @Override
        public Void visitSelect(SelectRelation relation, Void context) {
            if (relation.getSelectList() != null) {
                rejectHints(relation.getSelectList().getHintNodes());
            }
            return super.visitSelect(relation, context);
        }

        @Override
        public Void visitView(ViewRelation relation, Void context) {
            return null;
        }

        @Override
        public Void visitTable(TableRelation relation, Void context) {
            TableName name = relation.getName();
            if (name != null) {
                String schema = name.getDb() == null ? null : name.getDb().toUpperCase(Locale.ROOT);
                if (schema != null && FORBIDDEN_SCHEMAS.contains(schema)) {
                    deny(PrivilegeType.SELECT, ObjectType.DATABASE, schema);
                }
                if (isForbiddenConnectorMetadataTable(name.getTbl())) {
                    deny(PrivilegeType.SELECT, ObjectType.TABLE, name.getTbl());
                }
            }
            for (TableRelation.TableHint hint : relation.getTableHints()) {
                if (isForbiddenTableHint(hint.name())) {
                    deny(PrivilegeType.SELECT, ObjectType.TABLE, hint.name());
                }
            }
            return super.visitTable(relation, context);
        }

        @Override
        public Void visitFunctionCall(FunctionCallExpr function, Void context) {
            String functionName = function.getFnName().getFunction();
            if (isForbiddenFunction(functionName)) {
                denyFunction(functionName);
            }
            return visitExpression(function, context);
        }

        @Override
        public Void visitDictQueryExpr(DictQueryExpr function, Void context) {
            denyFunction("DICT_MAPPING");
            return null;
        }

        @Override
        public Void visitDictionaryGetExpr(DictionaryGetExpr function, Void context) {
            denyFunction("DICTIONARY_GET");
            return null;
        }

        @Override
        public Void visitTableFunction(TableFunctionRelation function, Void context) {
            String functionName = function.getFunctionName().getFunction();
            if (isForbiddenFunction(functionName)) {
                denyFunction(functionName);
            }
            return super.visitTableFunction(function, context);
        }

        @Override
        public Void visitFileTableFunction(FileTableFunctionRelation function, Void context) {
            denyFunction(FileTableFunctionRelation.IDENTIFIER);
            return null;
        }

        private static void rejectHints(List<HintNode> hints) {
            if (hints != null && !hints.isEmpty()) {
                deny(PrivilegeType.SELECT, ObjectType.SYSTEM, hints.get(0).toSql());
            }
        }
    }
}
