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

package com.starrocks.sql.optimizer.rule.mv;

import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.plan.PlanTestBase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class RangerManagedSynchronousMaterializedViewRewriteTest extends PlanTestBase {
    private static final String MATERIALIZED_VIEW = "ranger_managed_sync_mv";

    @BeforeAll
    public static void beforeClass() throws Exception {
        PlanTestBase.beforeClass();
        starRocksAssert.withMaterializedView("CREATE MATERIALIZED VIEW " + MATERIALIZED_VIEW + " AS " +
                "SELECT LO_ORDERDATE, COUNT(LO_LINENUMBER) FROM lineorder_flat_for_mv GROUP BY LO_ORDERDATE");
    }

    @AfterAll
    public static void dropMaterializedView() throws Exception {
        starRocksAssert.dropMaterializedView(MATERIALIZED_VIEW);
    }

    @Test
    public void testManagedQueryNeverUsesSynchronousMaterializedViewRewrite() throws Exception {
        String query = "SELECT LO_ORDERDATE, COUNT(LO_LINENUMBER) " +
                "FROM lineorder_flat_for_mv GROUP BY LO_ORDERDATE";

        String ordinaryPlan = getFragmentPlan(query);
        assertContains(ordinaryPlan, MATERIALIZED_VIEW);

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            String managedPlan = getFragmentPlan(query);
            assertNotContains(managedPlan, MATERIALIZED_VIEW);
            assertContains(managedPlan, "TABLE: lineorder_flat_for_mv");
        }
    }
}
