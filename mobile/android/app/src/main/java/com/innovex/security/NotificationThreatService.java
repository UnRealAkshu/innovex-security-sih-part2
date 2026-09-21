package com.innovex.security;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NotificationThreatService extends NotificationListenerService {
    private static final String CHANNEL_ID = "innovex_threats_v1";
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Set<String> inFlight = new HashSet<>();

    @Override
    public void onListenerConnected() {
        createChannel();
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null || getPackageName().equals(sbn.getPackageName())) return;

        Bundle extras = sbn.getNotification().extras;
        if (extras == null) return;

        StringBuilder combined = new StringBuilder();
        appendExtra(combined, extras.getCharSequence(Notification.EXTRA_TITLE));
        appendExtra(combined, extras.getCharSequence(Notification.EXTRA_TEXT));
        appendExtra(combined, extras.getCharSequence(Notification.EXTRA_BIG_TEXT));

        CharSequence[] lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES);
        if (lines != null) {
            for (CharSequence line : lines) appendExtra(combined, line);
        }

        String sharedText = combined.toString();
        final String url = UrlScanner.extractUrl(sharedText);
        if (url == null) return;

        synchronized (inFlight) {
            if (!inFlight.add(url)) return;
        }

        executor.execute(() -> {
            try {
                UrlScanner.Result result = UrlScanner.scan(url);
                if (result.riskScore >= 25) {
                    postThreatNotification(result, sbn.getPackageName());
                }
            } finally {
                synchronized (inFlight) {
                    inFlight.remove(url);
                }
            }
        });
    }

    private void appendExtra(StringBuilder builder, CharSequence value) {
        if (value == null) return;
        String text = value.toString().trim();
        if (text.isEmpty()) return;
        if (builder.length() > 0) builder.append('\n');
        builder.append(text);
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) return;

        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Innovex Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Warnings for suspicious links detected in app notifications.");
        manager.createNotificationChannel(channel);
    }

    private void postThreatNotification(UrlScanner.Result result, String sourcePackage) {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return;
        }

        createChannel();

        String label = result.severity.toUpperCase() + " risk link";
        String body = "Risk score " + result.riskScore + "/100 • Tap to review in Innovex.";

        Intent intent = new Intent(this, ShareScanActivity.class);
        intent.setAction(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TEXT, result.url);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                Math.abs(result.url.hashCode()),
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        String source = sourcePackage == null ? "another app" : sourcePackage;
        String details = result.indicators.isEmpty()
                ? "No indicator details were returned."
                : result.indicators.get(0);

        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);

        builder.setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("🛡 Innovex: " + label)
                .setContentText(body)
                .setStyle(new Notification.BigTextStyle()
                        .bigText(body + "\nSource: " + source + "\n" + details))
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setCategory(Notification.CATEGORY_WARNING)
                .setPriority(Notification.PRIORITY_HIGH);

        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(Math.abs(result.url.hashCode()), builder.build());
        }
    }

    @Override
    public void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}
