package com.innovex.security;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;

public final class ThreatAlertNotifier {
    private static final String CHANNEL_ID = "innovex_threats_v1";

    private ThreatAlertNotifier() {}

    public static void show(Context context, UrlScanner.Result result, String source) {
        if (Build.VERSION.SDK_INT >= 33
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        NotificationManager manager =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) return;

        createChannel(manager);

        String label = result.severity.toUpperCase() + " risk link";
        String body = "Risk score " + result.riskScore + "/100 • Tap to review in Innovex.";

        Intent intent = new Intent(context, ShareScanActivity.class);
        intent.setAction(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TEXT, result.url);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                context,
                Math.abs(result.url.hashCode()),
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        String sourceLabel = source == null || source.trim().isEmpty()
                ? "another app"
                : source;
        String details = result.indicators == null || result.indicators.isEmpty()
                ? "Innovex detected elevated risk indicators."
                : result.indicators.get(0);

        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(context, CHANNEL_ID)
                : new Notification.Builder(context);

        builder.setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("🛡 Innovex: " + label)
                .setContentText(body)
                .setStyle(new Notification.BigTextStyle()
                        .bigText(body + "\nSource: " + sourceLabel + "\n" + details))
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setCategory(Notification.CATEGORY_ERROR)
                .setPriority(Notification.PRIORITY_HIGH);

        manager.notify(Math.abs(result.url.hashCode()), builder.build());
    }

    private static void createChannel(NotificationManager manager) {
        if (Build.VERSION.SDK_INT < 26) return;

        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Innovex Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Warnings for suspicious links detected in app notifications.");
        manager.createNotificationChannel(channel);
    }
}
