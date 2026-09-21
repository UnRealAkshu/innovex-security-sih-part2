package com.innovex.security;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ShareScanActivity extends Activity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private int dp(float value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private TextView text(String value, float size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setPadding(0, dp(4), 0, dp(4));
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildLoadingView());
        handleIntent(getIntent());
    }

    private View buildLoadingView() {
        LinearLayout root = baseRoot();
        root.addView(text("Innovex Security", 24, Color.WHITE, true));
        root.addView(text("Checking this link before you open it…", 15, Color.rgb(170, 183, 208), false));

        ProgressBar progress = new ProgressBar(this);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(dp(48), dp(48));
        params.gravity = Gravity.CENTER_HORIZONTAL;
        params.topMargin = dp(28);
        root.addView(progress, params);

        return wrap(root);
    }

    private LinearLayout baseRoot() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(28), dp(24), dp(28));
        root.setBackgroundColor(Color.rgb(11, 16, 32));
        return root;
    }

    private ScrollView wrap(View view) {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.rgb(11, 16, 32));
        scroll.addView(view);
        return scroll;
    }

    private void handleIntent(Intent intent) {
        String sharedText = null;
        if (Intent.ACTION_SEND.equals(intent.getAction())) {
            sharedText = intent.getStringExtra(Intent.EXTRA_TEXT);
        } else if (Intent.ACTION_PROCESS_TEXT.equals(intent.getAction())) {
            sharedText = intent.getStringExtra(Intent.EXTRA_PROCESS_TEXT);
        }
        if (sharedText == null && intent.getData() != null) {
            sharedText = intent.getData().toString();
        }

        final String url = UrlScanner.extractUrl(sharedText);
        if (url == null) {
            showError("No web link was found", "Share a URL with Innovex Security and we will scan it automatically.");
            return;
        }

        executor.execute(() -> {
            final UrlScanner.Result result = UrlScanner.scan(url);
            runOnUiThread(() -> renderResult(result));
        });
    }

    private void renderResult(UrlScanner.Result result) {
        LinearLayout root = baseRoot();
        root.addView(text("Innovex Security", 24, Color.WHITE, true));
        root.addView(text(result.url, 13, Color.rgb(145, 160, 188), false));

        int severityColor = result.riskScore >= 75 ? Color.rgb(244, 88, 88)
                : result.riskScore >= 50 ? Color.rgb(255, 166, 77)
                : result.riskScore >= 25 ? Color.rgb(249, 206, 85)
                : Color.rgb(75, 210, 150);

        TextView score = text(result.riskScore + "/100", 42, Color.WHITE, true);
        score.setGravity(Gravity.CENTER);
        score.setPadding(0, dp(24), 0, dp(2));
        root.addView(score);

        TextView severity = text(result.severity.toUpperCase(), 16, severityColor, true);
        severity.setGravity(Gravity.CENTER);
        root.addView(severity);

        String title = result.riskScore >= 75 ? "⚠️ Critical risk detected"
                : result.riskScore >= 50 ? "⚠️ High risk detected"
                : result.riskScore >= 25 ? "Use caution"
                : "✓ No major risk indicators";
        root.addView(text(title, 19, Color.WHITE, true));

        TextView indicatorsTitle = text("Why Innovex scored this link", 15, Color.WHITE, true);
        indicatorsTitle.setPadding(0, dp(20), 0, dp(4));
        root.addView(indicatorsTitle);
        addIndicators(root, result.indicators);

        TextView recommendation = text(result.recommendation, 14, Color.rgb(241, 204, 138), false);
        recommendation.setPadding(0, dp(18), 0, dp(12));
        root.addView(recommendation);

        Button back = new Button(this);
        back.setText("Go Back");
        back.setOnClickListener(v -> finish());
        root.addView(back, new LinearLayout.LayoutParams(-1, dp(52)));

        Button open = new Button(this);
        open.setText(result.riskScore >= 50 ? "Continue anyway" : "Open Link");
        open.setOnClickListener(v -> {
            if (result.riskScore >= 50) {
                new AlertDialog.Builder(this)
                        .setTitle("Open risky link?")
                        .setMessage("Innovex detected elevated risk. Continue only if you trust the source.")
                        .setNegativeButton("Go Back", null)
                        .setPositiveButton("Open", (dialog, which) -> openUrl(result.url))
                        .show();
            } else {
                openUrl(result.url);
            }
        });

        LinearLayout.LayoutParams openParams = new LinearLayout.LayoutParams(-1, dp(52));
        openParams.topMargin = dp(10);
        root.addView(open, openParams);

        root.addView(text("Innovex Mobile • engine " + result.engineVersion, 11, Color.rgb(101, 116, 147), false));
        setContentView(wrap(root));
    }

    private void addIndicators(LinearLayout root, List<String> indicators) {
        if (indicators == null || indicators.isEmpty()) {
            root.addView(text("• No indicators returned.", 13, Color.rgb(190, 200, 220), false));
            return;
        }
        for (String indicator : indicators) {
            root.addView(text("• " + indicator, 13, Color.rgb(190, 200, 220), false));
        }
    }

    private void openUrl(String url) {
        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        finish();
    }

    private void showError(String title, String message) {
        LinearLayout root = baseRoot();
        root.addView(text(title, 23, Color.WHITE, true));
        root.addView(text(message, 15, Color.rgb(170, 183, 208), false));

        Button back = new Button(this);
        back.setText("Go Back");
        back.setOnClickListener(v -> finish());

        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, dp(52));
        p.topMargin = dp(24);
        root.addView(back, p);
        setContentView(wrap(root));
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}
