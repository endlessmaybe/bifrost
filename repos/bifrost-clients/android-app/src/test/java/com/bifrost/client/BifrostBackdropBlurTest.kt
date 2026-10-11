package com.bifrost.client

import com.bifrost.client.ui.components.bifrostBlurBackdropPixels
import org.junit.Assert.*
import org.junit.Test

class BifrostBackdropBlurTest {
    @Test fun constantWallpaperRetainsColorAndOpaqueEdges() {
        val pixels = IntArray(35) { 0xff193a57.toInt() }
        assertArrayEquals(pixels, bifrostBlurBackdropPixels(pixels, 7, 5, 3))
        assertArrayEquals(intArrayOf(0xff193a57.toInt()), bifrostBlurBackdropPixels(intArrayOf(0xff193a57.toInt()), 1, 1, 24))
    }

    @Test fun detailSoftensSymmetricallyWithoutChangingInputOrAlpha() {
        val pixels = IntArray(81) { 0xff000000.toInt() }.apply { this[40] = 0xffffffff.toInt() }
        val before = pixels.copyOf()
        val result = bifrostBlurBackdropPixels(pixels, 9, 9, 1)
        assertArrayEquals(before, pixels)
        assertTrue((result[40] and 255) in 1..254)
        assertTrue((result[39] and 255) > 0)
        assertEquals(result[39], result[41])
        assertEquals(result[31], result[49])
        assertTrue(result.all { it ushr 24 == 255 })
    }
}
