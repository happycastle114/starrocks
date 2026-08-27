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
package com.starrocks.authorization.ranger;

import com.starrocks.analysis.CastExpr;
import com.starrocks.analysis.Expr;
import com.starrocks.analysis.SlotRef;
import com.starrocks.analysis.TypeDef;
import com.starrocks.authorization.AccessDeniedException;
import com.starrocks.authorization.ExternalAccessController;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.catalog.Column;
import com.starrocks.catalog.StructField;
import com.starrocks.catalog.StructType;
import com.starrocks.catalog.Type;
import com.starrocks.common.util.SqlUtils;
import com.starrocks.qe.ConnectContext;
import com.starrocks.qe.SqlModeHelper;
import com.starrocks.sql.ast.UserIdentity;
import com.starrocks.sql.parser.ParsingException;
import com.starrocks.sql.parser.SqlParser;
import org.apache.commons.lang.StringUtils;
import org.apache.ranger.authorization.hadoop.config.RangerPluginConfig;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.policyengine.RangerPolicyEngine;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.Set;

import static com.starrocks.server.GlobalStateMgr.isCheckpointThread;
import static java.util.Locale.ENGLISH;

public abstract class RangerAccessController extends ExternalAccessController implements AccessTypeConverter {
    private static final Logger LOG = LoggerFactory.getLogger(RangerAccessController.class);
    private static final String COLUMN_PLACEHOLDER = "{col}";
    private static final String TYPE_PLACEHOLDER = "{type}";
    private static final String COLUMN_SENTINEL_PREFIX = "__starrocks_ranger_mask_column_";
    private static final String TYPE_SENTINEL_PREFIX = "__starrocks_ranger_mask_type_";
    protected final RangerBasePlugin rangerPlugin;

    public RangerAccessController(String serviceType, String serviceName) {
        RangerPluginConfig rangerPluginContext = buildRangerPluginContext(serviceType, serviceName);
        rangerPlugin = new RangerBasePlugin(rangerPluginContext);
        if (!isCheckpointThread()) {
            rangerPlugin.init(); // this will initialize policy engine and policy refresher
        }
        rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());

        LOG.info("Start Ranger plugin ({} - {}) success",
                rangerPluginContext.getServiceType(), rangerPluginContext.getServiceName());
    }

    protected RangerPluginConfig buildRangerPluginContext(String serviceType, String serviceName) {
        LOG.info("Interacting with Ranger Admin Server using SIMPLE authentication");
        return new RangerPluginConfig(serviceType, serviceName, serviceType,
                null, null, null);
    }

    public RangerBasePlugin getRangerPlugin() {
        return rangerPlugin;
    }

    public Expr getColumnMaskingExpression(RangerAccessResourceImpl resource, Column column, ConnectContext context) {
        RangerStarRocksAccessRequest request = RangerStarRocksAccessRequest.createAccessRequest(
                resource, context.getCurrentUserIdentity(), context.getGroups(),
                PrivilegeType.SELECT.name().toLowerCase(ENGLISH));

        RangerAccessResult result = rangerPlugin.evalDataMaskPolicies(request, null);
        if (result != null && result.isMaskEnabled()) {
            String maskType = result.getMaskType();
            RangerServiceDef.RangerDataMaskTypeDef maskTypeDef = result.getMaskTypeDef();
            String transformer = null;

            if (maskTypeDef != null) {
                transformer = maskTypeDef.getTransformer();
            }

            if (StringUtils.equalsIgnoreCase(maskType, RangerPolicy.MASK_TYPE_NULL)) {
                transformer = "NULL";
            } else if (StringUtils.equalsIgnoreCase(maskType, RangerPolicy.MASK_TYPE_CUSTOM)) {
                String maskedValue = result.getMaskedValue();
                transformer = Objects.requireNonNullElse(maskedValue, "NULL");
            }

            return parseColumnMaskTransformer(transformer, column);
        }

        return null;
    }

    private static Expr parseColumnMaskTransformer(String transformer, Column column) {
        int columnPlaceholderCount = StringUtils.countMatches(transformer, COLUMN_PLACEHOLDER);
        int typePlaceholderCount = StringUtils.countMatches(transformer, TYPE_PLACEHOLDER);
        String columnSentinel = findUnusedIdentifier(transformer, COLUMN_SENTINEL_PREFIX);
        String typeSentinel = findUnusedIdentifier(transformer, TYPE_SENTINEL_PREFIX);
        Type typeSentinelType = new StructType(List.of(new StructField(typeSentinel, Type.BIGINT)), true);

        String transformerWithSentinels = transformer
                .replace(COLUMN_PLACEHOLDER, columnSentinel)
                .replace(TYPE_PLACEHOLDER, typeSentinelType.toSql());
        Expr expression = SqlParser.parseSqlToExpr(transformerWithSentinels, SqlModeHelper.MODE_DEFAULT);

        int[] boundPlaceholderCounts = new int[2];
        expression = bindColumnMaskPlaceholders(
                expression, columnSentinel, typeSentinelType, column, boundPlaceholderCounts);
        if (boundPlaceholderCounts[0] != columnPlaceholderCount ||
                boundPlaceholderCounts[1] != typePlaceholderCount) {
            throw new ParsingException("Ranger column mask placeholder must be used in its exact expression context");
        }
        return expression;
    }

    private static Expr bindColumnMaskPlaceholders(Expr expression, String columnSentinel, Type typeSentinel,
                                                   Column column, int[] boundPlaceholderCounts) {
        if (expression instanceof SlotRef slotRef &&
                columnSentinel.equals(slotRef.getColumnName()) &&
                slotRef.getTblNameWithoutAnalyzed() == null) {
            boundPlaceholderCounts[0]++;
            return new SlotRef(null, column.getName(), SqlUtils.getIdentSql(column.getName()));
        }

        for (int i = 0; i < expression.getChildren().size(); i++) {
            expression.setChild(i, bindColumnMaskPlaceholders(
                    expression.getChild(i), columnSentinel, typeSentinel, column, boundPlaceholderCounts));
        }

        if (expression instanceof CastExpr castExpr) {
            TypeDef targetTypeDef = castExpr.getTargetTypeDef();
            if (targetTypeDef != null && typeSentinel.equals(targetTypeDef.getType())) {
                targetTypeDef.setType(column.getType());
                boundPlaceholderCounts[1]++;
            }
        }
        return expression;
    }

    private static String findUnusedIdentifier(String transformer, String prefix) {
        for (int suffix = 0; ; suffix++) {
            String candidate = prefix + suffix;
            if (!transformer.contains(candidate)) {
                return candidate;
            }
        }
    }

    protected Expr getRowAccessExpression(RangerAccessResourceImpl resource, ConnectContext context) {
        RangerStarRocksAccessRequest request = RangerStarRocksAccessRequest.createAccessRequest(
                resource, context.getCurrentUserIdentity(), context.getGroups(),
                PrivilegeType.SELECT.name().toLowerCase(ENGLISH));
        RangerAccessResult result = rangerPlugin.evalRowFilterPolicies(request, null);
        if (result != null && result.isRowFilterEnabled()) {
            return SqlParser.parseSqlToExpr(result.getFilterExpr(), SqlModeHelper.MODE_DEFAULT);
        } else {
            return null;
        }
    }

    protected void hasPermission(RangerAccessResourceImpl resource, UserIdentity user, Set<String> groups,
                                 PrivilegeType privilegeType)
            throws AccessDeniedException {
        // root user bypasses Ranger authorization entirely
        if (UserIdentity.ROOT.equals(user)) {
            return;
        }
        String accessType;
        if (privilegeType.equals(PrivilegeType.ANY)) {
            accessType = RangerPolicyEngine.ANY_ACCESS;
        } else {
            accessType = convertToAccessType(privilegeType);
        }

        RangerStarRocksAccessRequest request =
                RangerStarRocksAccessRequest.createAccessRequest(resource, user, groups, accessType);
        RangerAccessResult result = rangerPlugin.isAccessAllowed(request);
        if (result == null || !result.getIsAllowed()) {
            throw new AccessDeniedException();
        }
    }
}
