package com.bifrost.client.ui.components

import androidx.compose.foundation.Image
import androidx.compose.ui.res.painterResource
import com.bifrost.client.R
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.ui.platform.LocalContext
import android.provider.Settings
import com.bifrost.client.ui.model.BifrostConnectionState
import com.bifrost.client.ui.model.BifrostAndroidLayoutPlan
import com.bifrost.client.ui.model.BifrostMetricLayout
import com.bifrost.client.ui.model.BifrostPresentationState
import com.bifrost.client.ui.model.BifrostUiContract
import com.bifrost.client.ui.model.BifrostUiText
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun BifrostModeControl(selectedMode: String, onSelect: (String) -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val outerShape = RoundedCornerShape(18.dp)
    Row(
        modifier.fillMaxWidth()
            .clip(outerShape)
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = .16f))
            .border(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = .58f), outerShape)
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        BifrostUiContract.modes.forEach { (value, label) ->
            val active = selectedMode == value
            val interaction = remember { MutableInteractionSource() }
            val pressed by interaction.collectIsPressedAsState()
            Surface(
                color = if (active) MaterialTheme.colorScheme.primary.copy(alpha = 0.14f) else Color.Transparent,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).graphicsLayer { val scale = if (pressed) .98f else 1f; scaleX = scale; scaleY = scale }.clickable(enabled = enabled, interactionSource = interaction, indication = null) { onSelect(value) }.semantics {
                    contentDescription = label
                    role = Role.RadioButton
                    selected = active
                },
            ) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                    BifrostModeGlyph(value, active)
                    Spacer(Modifier.size(7.dp))
                    Text(label, color = if (active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp, fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal)
                }
            }
        }
    }
}

@Composable
private fun BifrostModeGlyph(mode: String, active: Boolean) {
    val color = if (active && mode == "smart") MaterialTheme.colorScheme.primary else if (active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant
    Canvas(Modifier.size(18.dp)) {
        val stroke = 1.45.dp.toPx()
        when (mode) {
            "smart" -> {
                val path = Path().apply {
                    moveTo(size.width * .57f, size.height * .04f)
                    lineTo(size.width * .20f, size.height * .52f)
                    lineTo(size.width * .48f, size.height * .52f)
                    lineTo(size.width * .37f, size.height * .96f)
                    lineTo(size.width * .82f, size.height * .43f)
                    lineTo(size.width * .54f, size.height * .43f)
                    close()
                }
                drawPath(path, color, style = Stroke(stroke))
            }
            "global" -> {
                val shield = Path().apply {
                    moveTo(size.width * .50f, size.height * .08f)
                    lineTo(size.width * .84f, size.height * .22f)
                    lineTo(size.width * .80f, size.height * .60f)
                    cubicTo(size.width * .76f, size.height * .76f, size.width * .62f, size.height * .88f, size.width * .50f, size.height * .95f)
                    cubicTo(size.width * .38f, size.height * .88f, size.width * .24f, size.height * .76f, size.width * .20f, size.height * .60f)
                    lineTo(size.width * .16f, size.height * .22f)
                    close()
                }
                drawPath(shield, color, style = Stroke(stroke))
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .34f, size.height * .50f), androidx.compose.ui.geometry.Offset(size.width * .46f, size.height * .62f), strokeWidth = stroke)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .46f, size.height * .62f), androidx.compose.ui.geometry.Offset(size.width * .68f, size.height * .37f), strokeWidth = stroke)
            }
            else -> {
                drawRoundRect(color, topLeft = androidx.compose.ui.geometry.Offset(size.width * .19f, size.height * .43f), size = androidx.compose.ui.geometry.Size(size.width * .62f, size.height * .48f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * .06f), style = Stroke(stroke))
                drawArc(color, startAngle = 180f, sweepAngle = 180f, useCenter = false, topLeft = androidx.compose.ui.geometry.Offset(size.width * .28f, size.height * .10f), size = androidx.compose.ui.geometry.Size(size.width * .44f, size.height * .56f), style = Stroke(stroke))
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .50f, size.height * .61f), androidx.compose.ui.geometry.Offset(size.width * .50f, size.height * .73f), strokeWidth = stroke)
            }
        }
    }
}

@Composable
fun BifrostConnectionRing(state: BifrostPresentationState, onClick: () -> Unit, useLightMaterial: Boolean = false, modifier: Modifier = Modifier.size(224.dp), enabled: Boolean = true) {
    val teardownState = state.isConnected || state.state == BifrostConnectionState.PREPARING ||
        state.state == BifrostConnectionState.RECONNECTING || state.state == BifrostConnectionState.BLOCKED
    val label = if (teardownState) BifrostUiText.disconnect else BifrostUiText.connectTunnel
    val context = LocalContext.current
    val reduceMotion = remember {
        runCatching { Settings.Global.getFloat(context.contentResolver, Settings.Global.TRANSITION_ANIMATION_SCALE, 1f) <= 0f }.getOrDefault(false)
    }
    val connecting = state.state == BifrostConnectionState.PREPARING || state.state == BifrostConnectionState.RECONNECTING
    val rotation = if (connecting && !reduceMotion) {
        val transition = rememberInfiniteTransition(label = "bifrost-connecting-dial")
        transition.animateFloat(0f, 360f, infiniteRepeatable(tween(900, easing = LinearEasing), RepeatMode.Restart), label = "connectingArc").value
    } else 0f
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val surfaceColor = MaterialTheme.colorScheme.surface
    val bronze = MaterialTheme.colorScheme.primary
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val outline = MaterialTheme.colorScheme.outline
    val statusColor = when {
        state.isConnected -> MaterialTheme.colorScheme.tertiary
        state.state == BifrostConnectionState.PREPARING -> Color(0xFF19CDD3)
        state.state == BifrostConnectionState.RECONNECTING -> Color(0xFF73CFC4)
        state.state == BifrostConnectionState.BLOCKED -> Color(0xFFD89A42)
        state.state == BifrostConnectionState.ERROR -> MaterialTheme.colorScheme.error
        else -> Color(0xFF4D7275)
    }
    Box(modifier.clip(CircleShape).graphicsLayer { val scale = if (pressed) .985f else 1f; scaleX = scale; scaleY = scale }.clickable(enabled = teardownState || (enabled && state.state == BifrostConnectionState.IDLE), interactionSource = interaction, indication = null) { onClick() }.semantics { contentDescription = label }, contentAlignment = Alignment.Center) {
        Canvas(Modifier.matchParentSize().padding(5.dp)) {
            val radius = size.minDimension * .455f
            drawCircle(surfaceColor.copy(alpha = .42f), radius = radius)
            drawCircle(Color.White.copy(alpha = .13f), radius = radius, style = Stroke(1.dp.toPx()))
            drawCircle(statusColor.copy(alpha = .10f), radius = radius, style = Stroke(8.dp.toPx()))
            drawCircle(statusColor.copy(alpha = .7f), radius = radius, style = Stroke(1.7.dp.toPx()))
            drawCircle(Color.White.copy(alpha = .07f), radius = radius * .84f, style = Stroke(1.dp.toPx()))
            if (connecting) drawArc(statusColor, startAngle = rotation - 90f, sweepAngle = 80f,
                useCenter = false, style = Stroke(3.dp.toPx()))
            if (pressed) drawCircle(Color.Black.copy(alpha = .13f), radius = radius)
        }
        Image(painterResource(R.drawable.bifrost_teal_rune_symbol), contentDescription = null,
            modifier = Modifier.size(82.dp), alpha = if (enabled || teardownState) .95f else .45f)

    }
}

@Composable
fun BifrostSummaryCard(title: String, value: String, modifier: Modifier = Modifier) {
    BifrostGlassCard(modifier) {
        Column(Modifier.padding(12.dp)) { Text(title, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp); Spacer(Modifier.height(4.dp)); Text(value, fontSize = 17.sp, fontWeight = FontWeight.SemiBold) }
    }
}

@Composable
fun BifrostMetricRow(state: BifrostPresentationState, layoutPlan: BifrostAndroidLayoutPlan, modifier: Modifier = Modifier) {
    val metrics = listOf(BifrostUiText.download to state.metrics.download, BifrostUiText.upload to state.metrics.upload, BifrostUiText.sessionTraffic to state.metrics.sessionTraffic, BifrostUiText.duration to state.metrics.duration)
    BifrostGlassCard(modifier.fillMaxWidth()) {
        androidx.compose.foundation.layout.Box(Modifier.fillMaxWidth().padding(12.dp)) {
            if (layoutPlan.metricLayout == BifrostMetricLayout.TWO_BY_TWO) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth()) { metrics.take(2).forEach { (label, value) -> MetricCell(label, value, Modifier.weight(1f)) } }
                    Row(Modifier.fillMaxWidth()) { metrics.drop(2).forEach { (label, value) -> MetricCell(label, value, Modifier.weight(1f)) } }
                }
            } else {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { metrics.forEach { (label, value) -> MetricCell(label, value, Modifier.weight(1f)) } }
            }
        }
    }
}

@Composable
private fun MetricCell(label: String, value: String, modifier: Modifier) {
    Column(modifier) { Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp); Text(value, fontSize = 16.sp, fontWeight = FontWeight.SemiBold) }
}

@Composable
fun BifrostBottomNavigation(selected: String, onSelect: (String) -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        listOf(
            "home" to BifrostUiText.home,
            "nodes" to BifrostUiText.nodes,
            "activity" to BifrostUiText.activity,
            "settings" to BifrostUiText.settings,
        ).forEach { (key, label) ->
            val active = selected == key
            val interaction = remember { MutableInteractionSource() }
            val pressed by interaction.collectIsPressedAsState()
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = if (active) MaterialTheme.colorScheme.primary.copy(alpha = .16f) else Color.Transparent,
                modifier = Modifier.weight(1f).padding(horizontal = 3.dp).height(54.dp)
                    .graphicsLayer { val scale = if (pressed) .98f else 1f; scaleX = scale; scaleY = scale }
                    .clickable(interactionSource = interaction, indication = null) { onSelect(key) }
                    .semantics {
                        contentDescription = label
                        this.selected = active
                        role = Role.Tab
                    },
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                    modifier = Modifier.fillMaxWidth().height(54.dp),
                ) {
                    BifrostNavGlyph(key, active)
                    Spacer(Modifier.height(3.dp))
                    Text(
                        label,
                        color = if (active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        fontSize = 11.sp,
                        textAlign = TextAlign.Center,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
private fun BifrostNavGlyph(key: String, active: Boolean) {
    val color = if (active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
    Canvas(Modifier.size(20.dp).padding(2.dp)) {
        val pen = Stroke(width = 1.5.dp.toPx())
        when (key) {
            "home" -> {
                drawCircle(color, radius = size.minDimension * .42f, style = pen)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .08f, size.height * .50f), androidx.compose.ui.geometry.Offset(size.width * .92f, size.height * .50f), strokeWidth = pen.width)
                drawOval(color, topLeft = androidx.compose.ui.geometry.Offset(size.width * .33f, size.height * .08f), size = androidx.compose.ui.geometry.Size(size.width * .34f, size.height * .84f), style = pen)
            }
            "nodes" -> {
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .12f, size.height * .18f), androidx.compose.ui.geometry.Offset(size.width * .45f, size.height * .48f), strokeWidth = pen.width)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .45f, size.height * .48f), androidx.compose.ui.geometry.Offset(size.width * .84f, size.height * .76f), strokeWidth = pen.width)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .12f, size.height * .18f), androidx.compose.ui.geometry.Offset(size.width * .31f, size.height * .10f), strokeWidth = pen.width)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .12f, size.height * .18f), androidx.compose.ui.geometry.Offset(size.width * .22f, size.height * .35f), strokeWidth = pen.width)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .84f, size.height * .76f), androidx.compose.ui.geometry.Offset(size.width * .66f, size.height * .69f), strokeWidth = pen.width)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .84f, size.height * .76f), androidx.compose.ui.geometry.Offset(size.width * .76f, size.height * .58f), strokeWidth = pen.width)
            }
            "activity" -> {
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .08f, size.height * .75f), androidx.compose.ui.geometry.Offset(size.width * .30f, size.height * .55f), strokeWidth = pen.width)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .30f, size.height * .55f), androidx.compose.ui.geometry.Offset(size.width * .48f, size.height * .68f), strokeWidth = pen.width)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .48f, size.height * .68f), androidx.compose.ui.geometry.Offset(size.width * .68f, size.height * .28f), strokeWidth = pen.width)
                drawLine(color, androidx.compose.ui.geometry.Offset(size.width * .68f, size.height * .28f), androidx.compose.ui.geometry.Offset(size.width * .92f, size.height * .43f), strokeWidth = pen.width)
            }
            else -> {
                drawCircle(color, radius = size.minDimension * .26f, style = pen)
                drawCircle(color, radius = size.minDimension * .08f, style = pen)
                for (step in 0 until 8) rotate(step * 45f) {
                    drawLine(color, androidx.compose.ui.geometry.Offset(center.x, center.y - size.height * .45f), androidx.compose.ui.geometry.Offset(center.x, center.y - size.height * .33f), strokeWidth = pen.width)
                }
            }
        }
    }
}
