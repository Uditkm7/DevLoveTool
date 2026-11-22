package com.developer.love.tool

import android.content.Context
import android.content.Intent
import android.view.LayoutInflater
import android.view.View
import android.widget.FrameLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.test.core.app.ApplicationProvider
import com.developer.love.tool.core.AppConstants
import com.developer.love.tool.ui.AppDetailsActivity
import com.developer.love.tool.ui.HistoryActivity
import com.google.android.material.bottomnavigation.BottomNavigationView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("DevLoveTool", appName)
  }

  @Test
  fun `main activity launches and switches redesigned sections cleanly`() {
    val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
    val activity = controller.get()

    val bottomNav = activity.findViewById<BottomNavigationView>(R.id.bottom_navigation)
    val sectionApps = activity.findViewById<View>(R.id.section_installed_apps)
    val sectionKs = activity.findViewById<View>(R.id.section_keystore_gen)
    val sectionAab = activity.findViewById<View>(R.id.section_apk_to_aab)

    assertNotNull(bottomNav)
    assertEquals(View.VISIBLE, sectionApps.visibility)
    assertEquals(View.GONE, sectionKs.visibility)
    assertEquals(View.GONE, sectionAab.visibility)

    bottomNav.selectedItemId = R.id.action_keystore_gen
    assertEquals(View.VISIBLE, sectionKs.visibility)
    assertEquals(View.GONE, sectionApps.visibility)
    assertEquals("100", activity.findViewById<TextView>(R.id.et_validity_years).text.toString())

    bottomNav.selectedItemId = R.id.action_apk_to_aab
    assertEquals(View.VISIBLE, sectionAab.visibility)
    assertEquals(View.GONE, sectionKs.visibility)
    assertNotNull(activity.findViewById<View>(R.id.btn_auto_fetch_alias))
    assertNotNull(activity.findViewById<View>(R.id.card_build_console))

    controller.pause().stop().destroy()
  }

  @Test
  fun `history activity launches and toggles segmented filter pills`() {
    val controller = Robolectric.buildActivity(HistoryActivity::class.java).setup()
    val activity = controller.get()

    val rgFilter = activity.findViewById<RadioGroup>(R.id.rg_history_filter)
    val rbAll = activity.findViewById<RadioButton>(R.id.rb_hist_all)
    val rbKeystores = activity.findViewById<RadioButton>(R.id.rb_hist_keystores)
    val rbAabs = activity.findViewById<RadioButton>(R.id.rb_hist_aabs)

    assertNotNull(rgFilter)
    assertTrue(rbAll.isChecked)

    rbKeystores.isChecked = true
    assertTrue(rbKeystores.isChecked)

    rbAabs.isChecked = true
    assertTrue(rbAabs.isChecked)

    controller.pause().stop().destroy()
  }

  @Test
  fun `app details activity binds redesigned views without inflation errors`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val intent = Intent(context, AppDetailsActivity::class.java).apply {
      putExtra(AppConstants.EXTRA_PACKAGE_NAME, context.packageName)
    }
    val controller = Robolectric.buildActivity(AppDetailsActivity::class.java, intent).setup()
    val activity = controller.get()

    assertNotNull(activity.findViewById<View>(R.id.btn_launch_app))
    assertNotNull(activity.findViewById<View>(R.id.btn_open_settings))
    assertNotNull(activity.findViewById<View>(R.id.btn_export_apk))
    assertNotNull(activity.findViewById<View>(R.id.tv_min_sdk))
    assertNotNull(activity.findViewById<View>(R.id.tv_target_sdk))
    assertNotNull(activity.findViewById<View>(R.id.tv_compile_sdk))
    assertNotNull(activity.findViewById<View>(R.id.layout_cert_container))

    controller.pause().stop().destroy()
  }

  @Test
  fun `all redesigned item and dialog layouts inflate cleanly under theme`() {
    val context = ApplicationProvider.getApplicationContext<Context>().apply {
      setTheme(R.style.Theme_DevLoveTool)
    }
    val inflater = LayoutInflater.from(context)
    val parent = FrameLayout(context)

    val layouts = listOf(
      R.layout.drawer_header,
      R.layout.dialog_searchable_app_picker,
      R.layout.item_app_row,
      R.layout.item_picker_app_row,
      R.layout.item_build_step,
      R.layout.item_history_keystore,
      R.layout.item_history_aab,
      R.layout.item_certificate_card,
      R.layout.item_permission_row,
      R.layout.item_component_section,
      R.layout.item_component_item
    )

    for (layoutRes in layouts) {
      val view = inflater.inflate(layoutRes, parent, false)
      assertNotNull(view)
    }
  }

  @Test
  fun `ime window insets hide bottom nav without double padding in MainActivity`() {
    val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
    val activity = controller.get()

    val decorView = activity.window.decorView
    val rootLayout = activity.findViewById<View>(R.id.root_layout)
    val contentFrame = activity.findViewById<View>(R.id.content_frame)
    val bottomNav = activity.findViewById<View>(R.id.bottom_navigation)
    val bottomDivider = activity.findViewById<View>(R.id.bottom_nav_divider)

    assertEquals(View.VISIBLE, bottomNav.visibility)
    assertEquals(View.VISIBLE, bottomDivider.visibility)

    // Simulate API <= 34 adjustResize: decor = 2000px, rootLayout already shrunk above 600px IME (bottom=1400)
    decorView.layout(0, 0, 1080, 2000)
    rootLayout.layout(0, 0, 1080, 1400)

    val imeOpenInsets = WindowInsetsCompat.Builder()
      .setInsets(WindowInsetsCompat.Type.systemBars(), Insets.of(0, 80, 0, 60))
      .setInsets(WindowInsetsCompat.Type.ime(), Insets.of(0, 0, 0, 600))
      .setVisible(WindowInsetsCompat.Type.ime(), true)
      .build()

    ViewCompat.dispatchApplyWindowInsets(rootLayout, imeOpenInsets)
    assertEquals(View.GONE, bottomNav.visibility)
    assertEquals(View.GONE, bottomDivider.visibility)
    assertEquals(0, contentFrame.paddingBottom)

    // Simulate API 35+ full-height edge-to-edge: rootLayout remains full height (bottom=2000)
    rootLayout.layout(0, 0, 1080, 2000)
    ViewCompat.dispatchApplyWindowInsets(rootLayout, imeOpenInsets)
    assertEquals(600, contentFrame.paddingBottom)

    // Simulate IME closed
    val imeClosedInsets = WindowInsetsCompat.Builder()
      .setInsets(WindowInsetsCompat.Type.systemBars(), Insets.of(0, 80, 0, 60))
      .setInsets(WindowInsetsCompat.Type.ime(), Insets.NONE)
      .setVisible(WindowInsetsCompat.Type.ime(), false)
      .build()

    ViewCompat.dispatchApplyWindowInsets(rootLayout, imeClosedInsets)
    assertEquals(View.VISIBLE, bottomNav.visibility)
    assertEquals(View.VISIBLE, bottomDivider.visibility)
    assertEquals(0, contentFrame.paddingBottom)

    controller.pause().stop().destroy()
  }
}
