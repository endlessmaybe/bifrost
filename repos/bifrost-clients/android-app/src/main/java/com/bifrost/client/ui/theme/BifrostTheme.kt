package com.bifrost.client.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val RuneCanvas = Color(0xFF07111E)
private val RuneSurface = Color(0xFF102336)
private val RuneElevated = Color(0xFF152C40)
private val RuneOutline = Color(0xFF365065)
private val RuneText = Color(0xFFE7F1F5)
private val RuneMuted = Color(0xFFADC0D2)
private val RuneCyan = Color(0xFF19CDD3)
private val RuneCyanSoft = Color(0xFF73CFC4)
private val RuneGreen = Color(0xFF20D4A5)
private val RuneWarning = Color(0xFFD8A25D)

data class BifrostDesignTokens(
    val pageHorizontal: Dp,
    val pageVertical: Dp,
    val sectionGap: Dp,
    val cardPadding: Dp,
    val cardRadius: Dp,
    val controlRadius: Dp,
    val heroMinDp: Int,
    val heroMaxDp: Int,
    val pageTitleSize: TextUnit,
    val brandRailWidth: Dp,
)

private val AuroraTokens = BifrostDesignTokens(20.dp, 14.dp, 16.dp, 18.dp, 20.dp, 16.dp, 176, 224, 24.sp, 0.dp)

val LocalBifrostDesign = staticCompositionLocalOf { AuroraTokens }

data class BifrostUiColors(
    val canvas: Color,
    val surface: Color,
    val surfaceElevated: Color,
    val outline: Color,
    val text: Color,
    val muted: Color,
    val accent: Color,
    val positive: Color,
    val warning: Color,
)

val BifrostDarkColors = BifrostUiColors(RuneCanvas, RuneSurface, RuneElevated, RuneOutline, RuneText, RuneMuted, RuneCyan, RuneGreen, RuneWarning)
@Composable
fun BifrostTheme(content: @Composable () -> Unit) {
    val colors = BifrostDarkColors
    val tokens = AuroraTokens
    val scheme: ColorScheme = darkColorScheme(
        primary = colors.accent,
        onPrimary = Color(0xFF001013),
        background = colors.canvas,
        onBackground = colors.text,
        surface = colors.surface,
        onSurface = colors.text,
        surfaceVariant = colors.surfaceElevated,
        onSurfaceVariant = colors.muted,
        outline = colors.outline,
        secondary = RuneCyanSoft,
        tertiary = colors.positive,
        error = Color(0xFFE05F66),
    )
    val typography = Typography(
        headlineSmall = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = tokens.pageTitleSize, fontWeight = FontWeight.SemiBold),
        titleMedium = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 16.sp, fontWeight = FontWeight.SemiBold),
        bodyMedium = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 14.sp, lineHeight = 20.sp),
        bodySmall = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 12.sp, lineHeight = 17.sp),
        labelLarge = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 14.sp, fontWeight = FontWeight.SemiBold),
    )
    CompositionLocalProvider(LocalBifrostDesign provides tokens,
        androidx.compose.material3.LocalContentColor provides colors.text) {
        MaterialTheme(
            colorScheme = scheme,
            typography = typography,
            shapes = Shapes(
                extraSmall = RoundedCornerShape(10.dp),
                small = RoundedCornerShape(tokens.controlRadius),
                medium = RoundedCornerShape(tokens.cardRadius),
                large = RoundedCornerShape(24.dp),
                extraLarge = RoundedCornerShape(28.dp),
            ),
            content = content,
        )
    }
}
