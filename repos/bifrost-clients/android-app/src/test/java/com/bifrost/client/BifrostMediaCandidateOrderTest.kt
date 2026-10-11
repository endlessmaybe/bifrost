package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class BifrostMediaCandidateOrderTest {
    @Test fun firstComparisonUsesHealthyResponsiveCandidateNotAlphabeticalFirst() {
        val rows = listOf(BifrostMeasuredCandidate("a-slow", 2300, 1), BifrostMeasuredCandidate("z-fast", 120, 1),
            BifrostMeasuredCandidate("dead", 0, 1), BifrostMeasuredCandidate("incumbent", 20, 1))
        assertEquals("z-fast", BifrostMediaCandidateOrder.challenger(rows, rows.map { it.tag }.toSet()-"dead", emptySet(), "incumbent", ""))
    }
    @Test fun aSlowerCandidateIsStillExploredWhenResponsiveCandidatesHaveBeenVisited() {
        val rows = listOf(BifrostMeasuredCandidate("slow", 1500, 1), BifrostMeasuredCandidate("fast", 80, 1))
        assertEquals("slow", BifrostMediaCandidateOrder.challenger(rows, setOf("slow","fast"),setOf("fast"),"current",""))
        assertNull(BifrostMediaCandidateOrder.challenger(rows,setOf("slow","fast"),setOf("slow","fast"),"current",""))
    }
    @Test fun signedThroughputOrderBeatsRttOrderForFirstChallenge() {
        val rows = listOf(BifrostMeasuredCandidate("low-rtt", 40, 1), BifrostMeasuredCandidate("ranked-fast", 220, 1))
        assertEquals("ranked-fast", BifrostMediaCandidateOrder.challenger(rows, rows.map { it.tag }.toSet(), emptySet(),
            "current", "", listOf("ranked-fast", "low-rtt")))
    }

    @Test fun staleProviderRankingStopsDominatingAfterBoundedSeed() {
        val rows = listOf(
            BifrostMeasuredCandidate("ranked-1", 900, 1),
            BifrostMeasuredCandidate("ranked-2", 800, 1),
            BifrostMeasuredCandidate("ranked-3", 700, 1),
            BifrostMeasuredCandidate("local-best", 35, 1),
        )
        val healthy = rows.map { it.tag }.toSet()
        val preferred = listOf("ranked-1", "ranked-2", "ranked-3", "local-best")
        assertEquals("ranked-1", BifrostMediaCandidateOrder.challenger(rows, healthy, emptySet(), "current", "", preferred))
        assertEquals("ranked-2", BifrostMediaCandidateOrder.challenger(rows, healthy, setOf("ranked-1"), "current", "", preferred))
        assertEquals("local-best", BifrostMediaCandidateOrder.challenger(
            rows, healthy, setOf("ranked-1", "ranked-2"), "current", "", preferred))
    }
}
