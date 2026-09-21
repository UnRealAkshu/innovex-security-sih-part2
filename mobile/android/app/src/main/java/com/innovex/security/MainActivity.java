package com.innovex.security;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.role.RoleManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
    private TextView messageStatus;
    private TextView browserStatus;
    private static final int REQUEST_NOTIFICATIONS = 101;
    private static final int REQUEST_BROWSER_ROLE = 102;

    private int dp(float value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private TextView text(String value, float size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestNotificationPermission();
        buildUi();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (messageStatus != null) updateProtectionStatus();
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQUEST_NOTIFICATIONS);
        }
    }

    private void buildUi() {
        ScrollView scrollView = new ScrollView(this);
        scrollView.setBackgroundColor(Color.rgb(11, 16, 32));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(28), dp(24), dp(28));

        TextView logo = text("I", 28, Color.WHITE, true);
        logo.setGravity(Gravity.CENTER);
        logo.setBackgroundColor(Color.rgb(103, 92, 255));
        root.addView(logo, new LinearLayout.LayoutParams(dp(54), dp(54)));

        TextView title = text("Innovex Security", 28, Color.WHITE, true);
        title.setPadding(0, dp(18), 0, dp(6));
        root.addView(title);
        root.addView(text(
                "Real-time protection that automatically finds links in messages and checks websites before they open.",
                15, Color.rgb(170, 183, 208), false));

        TextView protectionTitle = text("Protection", 19, Color.WHITE, true);
        protectionTitle.setPadding(0, dp(28), 0, dp(12));
        root.addView(protectionTitle);

        messageStatus = text("", 14, Color.rgb(170, 183, 208), false);
        messageStatus.setPadding(0, 0, 0, dp(6));
        root.addView(messageStatus);

        Button messageButton = new Button(this);
        messageButton.setText("Enable Message Protection");
        messageButton.setOnClickListener(v -> openNotificationAccess());
        root.addView(messageButton, new LinearLayout.LayoutParams(-1, dp(52)));

        browserStatus = text("", 14, Color.rgb(170, 183, 208), false);
        browserStatus.setPadding(0, dp(14), 0, dp(6));
        root.addView(browserStatus);

        Button webButton = new Button(this);
        webButton.setText("Enable Web Shield");
        webButton.setOnClickListener(v -> requestBrowserRole());
        LinearLayout.LayoutParams webParams = new LinearLayout.LayoutParams(-1, dp(52));
        webParams.topMargin = dp(4);
        root.addView(webButton, webParams);

        TextView autoTitle = text("Automatic link flow", 19, Color.WHITE, true);
        autoTitle.setPadding(0, dp(28), 0, dp(12));
        root.addView(autoTitle);

        root.addView(text(
                "• WhatsApp / Telegram / SMS notification → Innovex extracts the URL automatically → scan → risk alert.\n\n"
                        + "• Tap a web link → Innovex Web Shield receives the URL automatically → scan → Low / Medium / High / Critical → continue or go back.\n\n"
                        + "• Share a link from any app → Share → Innovex Security → the shared URL is extracted automatically. No URL needs to be hardcoded in the app.",
                13, Color.rgb(190, 200, 220), false));

        TextView testTitle = text("Quick test", 19, Color.WHITE, true);
        testTitle.setPadding(0, dp(28), 0, dp(12));
        root.addView(testTitle);

        final EditText testUrlInput = new EditText(this);
        testUrlInput.setHint("Paste a URL here for testing");
        testUrlInput.setSingleLine(true);
        testUrlInput.setTextColor(Color.WHITE);
        testUrlInput.setHintTextColor(Color.rgb(115, 128, 154));
        LinearLayout.LayoutParams inputParams = new LinearLayout.LayoutParams(-1, dp(52));
        root.addView(testUrlInput, inputParams);

        Button scanTest = new Button(this);
        scanTest.setText("Scan Test URL");
        scanTest.setOnClickListener(v -> {
            String value = testUrlInput.getText().toString().trim();
            if (value.isEmpty()) {
                testUrlInput.setError("Enter an HTTP(S) URL");
                return;
            }
            Intent intent = new Intent(this, ShareScanActivity.class);
            intent.setAction(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TEXT, value);
            startActivity(intent);
        });
        LinearLayout.LayoutParams scanParams = new LinearLayout.LayoutParams(-1, dp(52));
        scanParams.topMargin = dp(8);
        root.addView(scanTest, scanParams);

        Button shareHint = new Button(this);
        shareHint.setText("How the automatic protection works");
        shareHint.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Automatic protection")
                .setMessage(
                        "Production flow:\n\n"
                                + "• WhatsApp / Telegram / SMS notification → Innovex extracts the URL automatically.\n\n"
                                + "• Tap a web link → Innovex Web Shield receives the URL automatically.\n\n"
                                + "• Share text from any app → Innovex extracts the URL automatically.\n\n"
                                + "The box above is only a local test tool; users do not need to paste URLs during normal use.")
                .setPositiveButton("Got it", null)
                .show());
        root.addView(shareHint, new LinearLayout.LayoutParams(-1, dp(52)));

        root.addView(text(
                "Testing only: paste a URL above to exercise the same Innovex scanner. Normal users get URLs automatically from notifications, browser intents, or the Android share sheet.",
                12, Color.rgb(101, 116, 147), false));

        scrollView.addView(root);
        setContentView(scrollView);
        updateProtectionStatus();
    }

    private void updateProtectionStatus() {
        boolean listener = isNotificationListenerEnabled();
        messageStatus.setText(listener
                ? "🟢 Message Protection: ON"
                : "⚪ Message Protection: OFF — notification access required");
        messageStatus.setTextColor(listener
                ? Color.rgb(104, 221, 180)
                : Color.rgb(170, 183, 208));

        boolean browserRole = isBrowserRoleHeld();
        browserStatus.setText(browserRole
                ? "🟢 Web Shield: ON — Innovex is handling browser links"
                : "⚪ Web Shield: OFF — enable the browser role");
        browserStatus.setTextColor(browserRole
                ? Color.rgb(104, 221, 180)
                : Color.rgb(170, 183, 208));
    }

    private boolean isNotificationListenerEnabled() {
        String enabled = Settings.Secure.getString(
                getContentResolver(), "enabled_notification_listeners");
        if (enabled == null) return false;
        ComponentName component = new ComponentName(this, NotificationThreatService.class);
        return enabled.contains(component.flattenToString());
    }

    private void openNotificationAccess() {
        requestNotificationPermission();
        try {
            startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS));
        } catch (Exception e) {
            Toast.makeText(this, "Notification access settings are unavailable.", Toast.LENGTH_LONG).show();
        }
    }

    private boolean isBrowserRoleHeld() {
        if (Build.VERSION.SDK_INT < 29) return false;
        RoleManager roleManager = getSystemService(RoleManager.class);
        return roleManager != null
                && roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER)
                && roleManager.isRoleHeld(RoleManager.ROLE_BROWSER);
    }

    private void requestBrowserRole() {
        if (Build.VERSION.SDK_INT < 29) {
            new AlertDialog.Builder(this)
                    .setTitle("Web Shield")
                    .setMessage("This Android version does not support the browser-role flow used by Innovex.")
                    .setPositiveButton("OK", null)
                    .show();
            return;
        }

        RoleManager roleManager = getSystemService(RoleManager.class);
        if (roleManager == null || !roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER)) {
            Toast.makeText(this, "The browser role is not available on this device.", Toast.LENGTH_LONG).show();
            return;
        }

        if (roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
            Toast.makeText(this, "Web Shield is already enabled.", Toast.LENGTH_SHORT).show();
            return;
        }

        startActivityForResult(
                roleManager.createRequestRoleIntent(RoleManager.ROLE_BROWSER),
                REQUEST_BROWSER_ROLE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_BROWSER_ROLE) {
            updateProtectionStatus();
        }
    }
}
