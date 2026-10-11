package com.bifrost.client

import com.bifrost.client.ui.model.BifrostAndroidLayoutPolicy
import com.bifrost.client.ui.model.BifrostMetricLayout
import com.bifrost.client.ui.model.BifrostSummaryLayout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BifrostAndroidLayoutPolicyTest {
    @Test
    fun productionPolicyCoversRequiredViewportsAndFontScales() {
        for ((width, height) in listOf(360 to 640, 412 to 915)) {
            for (fontScale in listOf(1f, 1.3f, 2f)) {
                val plan = BifrostAndroidLayoutPolicy.forWidth(width, fontScale, height)
                assertEquals(48, plan.targetMinDp)
                assertEquals(listOf("连接", "线路", "活动", "设置"), plan.navigation)
                assertEquals(listOf("smart", "global", "smartgate"), plan.homeModes)
                assertTrue(plan.usesScroll)
                if (width < 420 || fontScale >= 1.8f) {
                    assertEquals(BifrostSummaryLayout.STACKED, plan.summaryLayout)
                    assertEquals(BifrostMetricLayout.TWO_BY_TWO, plan.metricLayout)
                    assertTrue(plan.wrapsText)
                } else {
                    assertEquals(BifrostSummaryLayout.INLINE, plan.summaryLayout)
                    assertEquals(BifrostMetricLayout.INLINE, plan.metricLayout)
                }
                assertTrue(plan.dialSizeDp in 168..224)
                assertTrue(plan.detailsAsSheet)
                val regions = listOf(plan.summaryRegion, plan.dialRegion, plan.statusRegion, plan.detailsRegion, plan.modeRegion)
                assertTrue(regions.all { it.within(plan.widthDp, plan.homeContentHeightDp) })
                regions.forEachIndexed { index, region ->
                    regions.drop(index + 1).forEach { other -> assertTrue(!region.intersects(other)) }
                }
                assertEquals(plan.dialSizeDp, plan.dialRegion.heightDp)
                assertTrue(plan.detailsRegion.heightDp >= 48)
                assertTrue(plan.modeRegion.heightDp >= 48)
            }
        }
    }

    @Test
    fun productionViewportPathUsesFinitePhysicalHeightAndFailsSafeWhenUnbounded() {
        val phone = BifrostAndroidLayoutPolicy.forViewport(412f, 915f, 1.3f)
        assertEquals(412, phone.widthDp)
        assertEquals(915, phone.heightDp)
        val narrow = BifrostAndroidLayoutPolicy.forViewport(360f, 640f, 2f)
        assertEquals(640, narrow.heightDp)
        assertEquals(BifrostSummaryLayout.STACKED, narrow.summaryLayout)
        assertEquals(168, narrow.dialSizeDp)
        assertTrue(narrow.detailsAsSheet)
        assertTrue(!narrow.usesThreePane)
        val tablet = BifrostAndroidLayoutPolicy.forViewport(800f, 900f, 1f)
        assertTrue(tablet.usesThreePane)
        assertEquals(BifrostSummaryLayout.INLINE, tablet.summaryLayout)
        val tabletRegions = listOf(tablet.dialRegion, tablet.statusRegion, tablet.detailsRegion, tablet.modeRegion)
        assertTrue(tabletRegions.all { it.within(tablet.widthDp, tablet.homeContentHeightDp) })
        assertTrue(tabletRegions.none { region -> tabletRegions.any { other -> region !== other && region.intersects(other) } })
        val unbounded = BifrostAndroidLayoutPolicy.forViewport(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY, 1f)
        assertEquals(1, unbounded.widthDp)
        assertEquals(1, unbounded.heightDp)
        assertEquals(BifrostSummaryLayout.STACKED, unbounded.summaryLayout)
        assertEquals(BifrostMetricLayout.TWO_BY_TWO, unbounded.metricLayout)
        val invalidScale = BifrostAndroidLayoutPolicy.forViewport(412f, 915f, 4f)
        assertEquals(BifrostSummaryLayout.STACKED, invalidScale.summaryLayout)
    }
}
