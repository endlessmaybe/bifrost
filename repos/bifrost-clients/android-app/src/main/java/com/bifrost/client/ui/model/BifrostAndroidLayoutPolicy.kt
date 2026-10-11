package com.bifrost.client.ui.model

/** Pure responsive policy used by the production Compose screen. */
enum class BifrostSummaryLayout { INLINE, STACKED }
enum class BifrostMetricLayout { INLINE, TWO_BY_TWO }

data class BifrostAndroidLayoutRegion(
    val name: String,
    val leftDp: Int,
    val topDp: Int,
    val widthDp: Int,
    val heightDp: Int,
) {
    val rightDp: Int get() = leftDp + widthDp
    val bottomDp: Int get() = topDp + heightDp

    fun intersects(other: BifrostAndroidLayoutRegion): Boolean =
        widthDp > 0 && heightDp > 0 && other.widthDp > 0 && other.heightDp > 0 &&
            leftDp < other.rightDp && rightDp > other.leftDp && topDp < other.bottomDp && bottomDp > other.topDp

    fun within(width: Int, height: Int): Boolean =
        leftDp >= 0 && topDp >= 0 && rightDp <= width && bottomDp <= height
}

data class BifrostAndroidLayoutPlan(
    val widthDp: Int,
    val heightDp: Int,
    val fontScale: Float,
    val summaryLayout: BifrostSummaryLayout,
    val metricLayout: BifrostMetricLayout,
    val targetMinDp: Int = 48,
    val navigation: List<String> = BifrostUiContract.navigation,
    val homeModes: List<String> = listOf("smart", "global", "smartgate"),
    val usesScroll: Boolean,
    val wrapsText: Boolean,
    /** Production dial size; compact plans shrink the vector, never the hit target. */
    val dialSizeDp: Int = 224,
    /** Whether route/quality/session details should be offered as a bottom sheet. */
    val detailsAsSheet: Boolean = true,
    /** Tablet/landscape uses a real three-column workspace instead of a stretched phone. */
    val usesThreePane: Boolean = false,
    /** Compact summary avoids three unconstrained cards at large font scales. */
    val compactSummary: Boolean = false,
    /** Reserved regions are in the HomeContent coordinate space, not guesses via padding. */
    val topReservedDp: Int = 0,
    val homeContentHeightDp: Int = 1,
    val summaryRegion: BifrostAndroidLayoutRegion = BifrostAndroidLayoutRegion("summary", 0, 0, 0, 0),
    val dialRegion: BifrostAndroidLayoutRegion = BifrostAndroidLayoutRegion("dial", 0, 0, 0, 0),
    val statusRegion: BifrostAndroidLayoutRegion = BifrostAndroidLayoutRegion("status", 0, 0, 0, 0),
    val detailsRegion: BifrostAndroidLayoutRegion = BifrostAndroidLayoutRegion("details", 0, 0, 0, 0),
    val modeRegion: BifrostAndroidLayoutRegion = BifrostAndroidLayoutRegion("mode", 0, 0, 0, 0),
)

object BifrostAndroidLayoutPolicy {
    /**
     * Converts the finite constraints of the outer screen viewport into a
     * production plan.  Inner verticalScroll children are intentionally not
     * allowed to derive a height: their maxHeight may be Infinity. Invalid or
     * overflowing constraints fail safe to the most conservative wrapped
     * layout instead of silently falling back to a fake 640dp viewport.
     */
    fun forViewport(widthDp: Float, heightDp: Float, fontScale: Float): BifrostAndroidLayoutPlan {
        val valid = widthDp.isFinite() && heightDp.isFinite() && widthDp > 0f && heightDp > 0f &&
            widthDp <= Int.MAX_VALUE && heightDp <= Int.MAX_VALUE && fontScale.isFinite() && fontScale in 1f..3f
        if (!valid) return conservativePlan(fontScale)
        return forWidth(widthDp.toInt().coerceAtLeast(1), fontScale, heightDp.toInt().coerceAtLeast(1))
    }

    /**
     * Width-only callers are intentionally not supported: a layout plan is
     * valid only when it is bound to the finite outer viewport height too.
     */
    fun forWidth(widthDp: Int, fontScale: Float, heightDp: Int): BifrostAndroidLayoutPlan {
        require(widthDp > 0 && heightDp > 0) { "BF-UI-VIEWPORT" }
        require(fontScale in 1f..3f) { "BF-UI-FONTSCALE" }
        val constrained = widthDp < 420 || fontScale >= 1.8f
        val short = heightDp < 700
        // Phone layouts use one bounded, wrapped summary. Full source/route/
        // core cards belong to the details sheet so large type never collides
        // with the dial or the bottom controls.
        val compactSummary = widthDp < 600 || fontScale >= 1.3f || (short && widthDp < 720)
        val dialSize = when {
            widthDp < 380 && fontScale >= 1.8f -> 168
            widthDp < 380 -> 188
            fontScale >= 1.8f -> 184
            widthDp < 420 -> 200
            short -> 204
            else -> 224
        }
        val topBarReserved = 72
        val bottomNavigationReserved = 72
        val homeHeight = (heightDp - topBarReserved - bottomNavigationReserved).coerceAtLeast(1)
        val compactSummaryHeight = if (fontScale >= 1.8f) 72 else 48
        val topReserved = when {
            usesThreePane(widthDp, fontScale) -> 0
            compactSummary -> compactSummaryHeight
            constrained -> 154
            else -> 72
        }
        val modeHeight = 56
        val detailsHeight = 48
        val modeTop = (homeHeight - modeHeight - 12).coerceAtLeast(0)
        val detailsTop = (modeTop - detailsHeight - 8).coerceAtLeast(topReserved)
        val statusHeight = if (compactSummary) 48 else 52
        val usableBottom = (detailsTop - 8).coerceAtLeast(topReserved + statusHeight + 120)
        val resolvedDialSize = dialSize.coerceAtMost((usableBottom - topReserved - statusHeight - 8).coerceAtLeast(120))
        val centeredTop = ((homeHeight - resolvedDialSize - statusHeight) / 2).coerceIn(topReserved, (usableBottom - resolvedDialSize - 8 - statusHeight).coerceAtLeast(topReserved))
        val summaryHeight = when {
            usesThreePane(widthDp, fontScale) -> 0
            compactSummary -> compactSummaryHeight
            constrained -> 154
            else -> 72
        }
        val summary = BifrostAndroidLayoutRegion("summary", 16, 0, (widthDp - 32).coerceAtLeast(1), summaryHeight)
        val dial = BifrostAndroidLayoutRegion("dial", 0, centeredTop, widthDp, resolvedDialSize)
        val status = BifrostAndroidLayoutRegion("status", 16, centeredTop + resolvedDialSize + 8, (widthDp - 32).coerceAtLeast(1), statusHeight)
        val details = BifrostAndroidLayoutRegion("details", 16, detailsTop, (widthDp - 32).coerceAtLeast(1), detailsHeight)
        val mode = BifrostAndroidLayoutRegion("mode", 0, modeTop, widthDp, modeHeight)
        return BifrostAndroidLayoutPlan(
            widthDp = widthDp,
            heightDp = heightDp,
            fontScale = fontScale,
            summaryLayout = if (constrained) BifrostSummaryLayout.STACKED else BifrostSummaryLayout.INLINE,
            metricLayout = if (constrained) BifrostMetricLayout.TWO_BY_TWO else BifrostMetricLayout.INLINE,
            usesScroll = true,
            wrapsText = constrained,
            dialSizeDp = resolvedDialSize,
            detailsAsSheet = true,
            usesThreePane = usesThreePane(widthDp, fontScale),
            compactSummary = compactSummary,
            topReservedDp = topReserved,
            homeContentHeightDp = homeHeight,
            summaryRegion = summary,
            dialRegion = dial,
            statusRegion = status,
            detailsRegion = details,
            modeRegion = mode,
        )
    }

    private fun usesThreePane(widthDp: Int, fontScale: Float): Boolean = widthDp >= 720 && fontScale < 1.8f

    private fun conservativePlan(fontScale: Float): BifrostAndroidLayoutPlan = BifrostAndroidLayoutPlan(
        widthDp = 1,
        heightDp = 1,
        fontScale = if (fontScale.isFinite() && fontScale > 0f) fontScale else 1f,
        summaryLayout = BifrostSummaryLayout.STACKED,
        metricLayout = BifrostMetricLayout.TWO_BY_TWO,
        usesScroll = true,
        wrapsText = true,
        compactSummary = true,
    )
}
