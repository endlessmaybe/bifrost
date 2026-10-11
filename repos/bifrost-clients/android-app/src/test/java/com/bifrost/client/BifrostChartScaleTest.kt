package com.bifrost.client

import com.bifrost.client.ui.model.BifrostChartScale
import org.junit.Assert.assertEquals
import org.junit.Test

class BifrostChartScaleTest {
    @Test fun rateScaleUsesBothSeriesAndHandlesStartupAndInvalidSamples() {
        assertEquals(1024f, BifrostChartScale.maximum(emptyList()), 0f)
        assertEquals(1024f, BifrostChartScale.maximum(listOf(-1f, Float.NaN, Float.POSITIVE_INFINITY)), 0f)
        assertEquals(8f * 1024 * 1024, BifrostChartScale.maximum(listOf(1024f, 7.2f * 1024 * 1024)), 0f)
        assertEquals("0 B/s", BifrostChartScale.rate(Float.NaN))
        assertEquals("512 KB/s", BifrostChartScale.rate(512f * 1024))
        assertEquals("1.5 MB/s", BifrostChartScale.rate(1.5f * 1024 * 1024))
    }
}
