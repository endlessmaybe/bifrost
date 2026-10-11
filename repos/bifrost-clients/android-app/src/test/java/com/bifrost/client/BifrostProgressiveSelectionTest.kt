package com.bifrost.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BifrostProgressiveSelectionTest {
    @Test fun firstHealthyThenBetterResultsProgressWithoutWaitingForTheLastNode() {
        val allowed = setOf("A-1", "A-2", "A-3")
        val first = listOf(BifrostMeasuredCandidate("A-1", 280, 2000))
        assertEquals("A-1", BifrostProgressiveSelection.best(allowed, first, 2001))
        assertEquals("A-2", BifrostProgressiveSelection.best(allowed, first + BifrostMeasuredCandidate("A-2", 160, 2002), 2003))
        assertEquals("A-3", BifrostProgressiveSelection.best(allowed, first + listOf(BifrostMeasuredCandidate("A-2", 160, 2002), BifrostMeasuredCandidate("A-3", 120, 2004)), 2005))
    }
    @Test fun foreignStaleUnmeasuredAndFailedNodesCannotBeSelected() {
        assertNull(BifrostProgressiveSelection.best(setOf("A-1"), listOf(
            BifrostMeasuredCandidate("B-1", 1, 2000), BifrostMeasuredCandidate("A-1", 0, 2000),
            BifrostMeasuredCandidate("A-1", 100, 0), BifrostMeasuredCandidate("A-1", 100, 1),
        ), 2001))
    }

    @Test fun automaticSelectionKeepsHealthyIncumbentInsideToleranceButLeavesSlowPath() {
        val allowed = setOf("A-1", "A-2", "A-3")
        val rows = listOf(
            BifrostMeasuredCandidate("A-1", 100, 2000),
            BifrostMeasuredCandidate("A-2", 135, 2000),
            BifrostMeasuredCandidate("A-3", 190, 2000),
        )
        assertEquals(setOf("A-1", "A-2"), BifrostProgressiveSelection.latencyWindow(allowed, rows, 2001))
        assertEquals("A-2", BifrostProgressiveSelection.stableBest(allowed, rows, 2001, "A-2"))
        assertEquals("A-1", BifrostProgressiveSelection.stableBest(allowed, rows, 2001, "A-3"))
    }

    @Test fun throughputQualificationDoesNotDiscardHigherLatencyHealthyPath() {
        val allowed = setOf("A-low-rtt", "A-high-bandwidth")
        val rows = listOf(
            BifrostMeasuredCandidate("A-low-rtt", 40, 2000),
            BifrostMeasuredCandidate("A-high-bandwidth", 240, 2000),
        )
        assertEquals(setOf("A-low-rtt"), BifrostProgressiveSelection.latencyWindow(allowed, rows, 2001))
        assertEquals(allowed, BifrostProgressiveSelection.throughputEligible(allowed, rows, 2001))
    }
}
