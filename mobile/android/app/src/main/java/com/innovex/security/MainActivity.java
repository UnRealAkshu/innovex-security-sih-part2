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
        root.addView(text("Real-time mobile protection for links in messages and websites.", 15,
                Color.rgb(170, 183, 208), false));

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

        TextView flow = text(
                "Message protection: notification → URL extraction → Innovex scan → risk alert.\n\n"
                        + "Web Shield: browser link → Innovex scan → warning → continue or go back.",
                13, Color.rgb(190, 200, 220), false);
        flow.setPadding(0, dp(18), 0, 0);
        root.addView(flow);

        TextView testTitle = text("Testing", 19, Color.WHITE, true);
        testTitle.setPadding(0, dp(28), 0, dp(12));
        root.addView(testTitle);

        Button demo = new Button(this);
        demo.setText("Test a URL manually");
        demo.setOnClickListener(v -> {
            Intent intent = new Intent(this, ShareScanActivity.class);
            intent.setAction(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TEXT,
                    "https://example.com/login/verify/account/password/secure/update/confirm/bank/payment/wallet?user=1&verify=2&password=3&account=4&secure=5&token=6");
            startActivity(intent);
        });
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(-1, dp(52));
        buttonParams.topMargin = dp(4);
        root.addView(demo, buttonParams);

        root.addView(text(
                "Message protection requires notification access. Web Shield can ask Android to make Innovex the default browser.",
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
