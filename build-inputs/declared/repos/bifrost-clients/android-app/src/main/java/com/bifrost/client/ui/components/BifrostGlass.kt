package com.bifrost.client.ui.components

import android.graphics.BitmapFactory
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.HorizontalDivider
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import com.bifrost.client.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.math.roundToInt

/** One wallpaper layer is softened once; text and controls never enter a blur
 * layer. Reduced-resolution decoding keeps the Android 9 fallback inexpensive. */
@Composable
fun BifrostBackdrop(modifier: Modifier = Modifier) {
    val resources = LocalContext.current.resources
    val configuration = LocalConfiguration.current
    val density = LocalDensity.current.density
    val width = configuration.screenWidthDp * density
    val height = configuration.screenHeightDp * density
    var bitmap by remember(resources) { mutableStateOf<ImageBitmap?>(null) }
    LaunchedEffect(resources, width, height, density) {
        bitmap = withContext(Dispatchers.IO) {
            val decoded = BitmapFactory.decodeResource(resources, R.drawable.bifrost_aurora_background,
                BitmapFactory.Options().apply { inSampleSize = 8; inPreferredConfig = Bitmap.Config.ARGB_8888 })
            decoded?.let {
                // Blur the small wallpaper once, instead of maintaining a
                // full-screen GPU blur render target on every UI frame.
                val scale = maxOf(width / it.width, height / it.height).coerceAtLeast(1f)
                val radius = (18f * density / scale).roundToInt().coerceIn(1, 24)
                val pixels = IntArray(it.width * it.height)
                it.getPixels(pixels, 0, it.width, 0, 0, it.width, it.height)
                val blurred = bifrostBlurBackdropPixels(pixels, it.width, it.height, radius)
                Bitmap.createBitmap(blurred, it.width, it.height, Bitmap.Config.ARGB_8888)
                    .asImageBitmap().also { _ -> it.recycle() }
            }
        }
    }
    bitmap?.let { Image(it, null, modifier, contentScale = ContentScale.Crop, alpha = .86f) }
}

/** Three separable box passes approximate a soft Gaussian at thumbnail scale.
 * Edge clamping avoids dark borders when the wallpaper is cropped to fill. */
internal fun bifrostBlurBackdropPixels(pixels: IntArray, width: Int, height: Int, radius: Int): IntArray {
    require(width > 0 && height > 0 && pixels.size == width * height && radius in 1..24)
    var source = pixels.copyOf()
    var target = IntArray(source.size)
    val window = radius * 2 + 1
    repeat(3) {
        for (horizontal in listOf(true, false)) {
            val lines = if (horizontal) height else width
            val length = if (horizontal) width else height
            val step = if (horizontal) 1 else width
            for (line in 0 until lines) {
                val base = if (horizontal) line * width else line
                var alpha = 0; var red = 0; var green = 0; var blue = 0
                fun accumulate(position: Int, sign: Int) {
                    val pixel = source[base + position.coerceIn(0, length - 1) * step]
                    alpha += (pixel ushr 24) * sign
                    red += ((pixel ushr 16) and 255) * sign
                    green += ((pixel ushr 8) and 255) * sign
                    blue += (pixel and 255) * sign
                }
                for (offset in -radius..radius) accumulate(offset, 1)
                for (position in 0 until length) {
                    target[base + position * step] = ((alpha / window) shl 24) or
                        ((red / window) shl 16) or ((green / window) shl 8) or (blue / window)
                    accumulate(position - radius, -1)
                    accumulate(position + radius + 1, 1)
                }
            }
            val previous = source; source = target; target = previous
        }
    }
    return source
}

@Composable
fun BifrostGlassCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    // Sections share the page's single frosted surface. A quiet rule provides
    // hierarchy without another rectangle, shadow, or repeated gradient.
    Column(modifier = modifier) {
        content()
        HorizontalDivider(Modifier.fillMaxWidth(), thickness = .5.dp, color = Color(0x18D4E8FA))
    }
}
