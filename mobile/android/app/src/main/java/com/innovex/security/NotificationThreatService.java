package com.innovex.security;

import android.app.Notification;
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
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Set<String> inFlight = new HashSet<>();

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

    private void postThreatNotification(UrlScanner.Result result, String sourcePackage) {
        ThreatAlertNotifier.show(this, result, sourcePackage);
    }

    @Override
    public void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}
