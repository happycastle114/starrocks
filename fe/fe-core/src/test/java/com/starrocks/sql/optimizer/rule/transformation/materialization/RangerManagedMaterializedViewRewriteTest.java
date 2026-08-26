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

package com.starrocks.sql.optimizer.rule.transformation.materialization;

import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.plan.PlanTestBase;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class RangerManagedMaterializedViewRewriteTest extends MVTestBase {
    @BeforeAll
    public static void beforeClass() throws Exception {
        MVTestBase.beforeClass();
        starRocksAssert.withTable(cluster, "depts");
        starRocksAssert.withTable(cluster, "emps");
    }

    @Test
    public void testManagedQueryNeverUsesAsyncMaterializedViewRewrite() throws Exception {
        createAndRefreshMv("CREATE MATERIALIZED VIEW managed_rewrite_mv DISTRIBUTED BY HASH(empid) " +
                "AS SELECT empid, deptno, name, salary FROM emps WHERE empid = 5");
        String query = "SELECT empid, deptno, name, salary FROM emps WHERE empid = 5";

        String ordinaryPlan = getFragmentPlan(query);
        PlanTestBase.assertContains(ordinaryPlan, "TABLE: managed_rewrite_mv");

        try (MockedStatic<Authorizer> authorizer =
                     Mockito.mockStatic(Authorizer.class, Mockito.CALLS_REAL_METHODS)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(connectContext)).thenReturn(true);

            String managedPlan = getFragmentPlan(query);
            PlanTestBase.assertNotContains(managedPlan, "managed_rewrite_mv");
            PlanTestBase.assertContains(managedPlan, "TABLE: emps");
        } finally {
            dropMv("test", "managed_rewrite_mv");
        }
    }

}
