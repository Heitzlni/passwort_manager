package com.example.passwort_manager.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val DarkColors = darkColorScheme(
    primary = PurpleVivid,
    onPrimary = OnSurfaceDark,
    primaryContainer = PurpleContainerDark,
    onPrimaryContainer = PurpleGlow,
    secondary = PurpleTint,
    onSecondary = OnSurfaceDark,
    tertiary = PurpleGlow,
    background = SurfaceDark,
    onBackground = OnSurfaceDark,
    surface = SurfaceDark,
    onSurface = OnSurfaceDark,
    surfaceVariant = SurfaceVariantDark,
    onSurfaceVariant = OnSurfaceVariantDark,
)

private val LightColors = lightColorScheme(
    primary = PurpleBrand,
    onPrimary = OnSurfaceLight.copy(alpha = 0.0f).copy(red = 1f, green = 1f, blue = 1f),
    primaryContainer = PurpleContainerLight,
    onPrimaryContainer = PurpleDeep,
    secondary = PurpleDeep,
    onSecondary = SurfaceLight,
    tertiary = PurpleBrand,
    background = SurfaceLight,
    onBackground = OnSurfaceLight,
    surface = SurfaceLight,
    onSurface = OnSurfaceLight,
    surfaceVariant = SurfaceVariantLight,
    onSurfaceVariant = OnSurfaceVariantLight,
)

/**
 * App theme. Dynamic color (Material You) is deliberately OFF so the
 * brand purple comes through on every phone — otherwise on Material
 * You devices the launcher's wallpaper-derived palette overrides us
 * and the app reads as generic blue/green/whatever the user's
 * wallpaper happens to be.
 */
@Composable
fun Passwort_ManagerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) DarkColors else LightColors
    MaterialTheme(
        colorScheme = colors,
        typography = Typography,
        content = content,
    )
}
