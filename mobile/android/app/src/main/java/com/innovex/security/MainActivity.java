package com.innovex.security;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {
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
        root.addView(text("Share a suspicious link with Innovex before opening it.", 15, Color.rgb(170, 183, 208), false));

        TextView stepTitle = text("How it works", 18, Color.WHITE, true);
        stepTitle.setPadding(0, dp(28), 0, dp(12));
        root.addView(stepTitle);

        String[] steps = {
                "1. In WhatsApp, Telegram, Chrome or another app, tap Share.",
                "2. Select Innovex Security.",
                "3. Innovex scans the URL automatically.",
                "4. Low/Medium links can be opened; High/Critical links are clearly warned about."
        };
        for (String step : steps) {
            TextView t = text(step, 14, Color.rgb(218, 225, 240), false);
            t.setPadding(0, 0, 0, dp(14));
            root.addView(t);
        }

        TextView status = text("Ready for shared links", 14, Color.rgb(104, 221, 180), true);
        status.setPadding(dp(14), dp(14), dp(14), dp(14));
        root.addView(status);

        Button demo = new Button(this);
        demo.setText("Test a URL manually");
        demo.setOnClickListener(v -> {
            Intent intent = new Intent(this, ShareScanActivity.class);
            intent.setAction(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TEXT, "https://example.com/login/verify/account/password/secure/update");
            startActivity(intent);
        });
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(-1, dp(52));
        buttonParams.topMargin = dp(24);
        root.addView(demo, buttonParams);

        root.addView(text("Android uses ACTION_SEND text/plain to expose Innovex in the system share sheet.", 12, Color.rgb(101, 116, 147), false));

        scrollView.addView(root);
        setContentView(scrollView);
    }
}
