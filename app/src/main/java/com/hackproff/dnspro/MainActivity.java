package com.hackproff.dnspro;

import android.app.Activity;
import android.content.Intent;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.*;
import android.view.Gravity;
import android.view.View;
import android.widget.*;

public class MainActivity extends Activity {
    static final int REQ = 1;
    Button btn; TextView status;
    Handler h = new Handler();
    Runnable tick = new Runnable() { public void run() { refresh(); h.postDelayed(this, 1000); } };

    int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density); }

    @Override protected void onCreate(Bundle s) {
        super.onCreate(s);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL); root.setGravity(Gravity.CENTER);
        root.setBackgroundColor(0xFF0B1E3A); root.setPadding(dp(24), dp(24), dp(24), dp(24));
        ImageView logo = new ImageView(this); logo.setImageResource(R.mipmap.ic_launcher);
        root.addView(logo, new LinearLayout.LayoutParams(dp(110), dp(110)));
        TextView t = new TextView(this); t.setText("DNSPRO"); t.setTextSize(30);
        t.setTextColor(0xFFFFFFFF); t.setGravity(Gravity.CENTER); t.setPadding(0, dp(12), 0, dp(4));
        root.addView(t);
        status = new TextView(this); status.setTextSize(16); status.setGravity(Gravity.CENTER);
        status.setPadding(0, 0, 0, dp(28)); root.addView(status);
        btn = new Button(this); btn.setTextColor(0xFFFFFFFF); btn.setTextSize(18);
        btn.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
            if (DnsVpnService.running) stop(); else start(); } });
        root.addView(btn, new LinearLayout.LayoutParams(dp(240), dp(60)));
        TextView info = new TextView(this);
        info.setText("Bloqueio de anúncios e rastreadores via AdGuard DNS.\nInicia sozinho com o celular.");
        info.setTextColor(0xFF8FA6C8); info.setGravity(Gravity.CENTER); info.setPadding(0, dp(28), 0, 0);
        root.addView(info);
        setContentView(root);
        if (getSharedPreferences("p", 0).getBoolean("enabled", true) && !DnsVpnService.running) start();
    }

    void start() {
        Intent i = VpnService.prepare(this);
        if (i != null) startActivityForResult(i, REQ); else go();
    }
    void go() {
        getSharedPreferences("p", 0).edit().putBoolean("enabled", true).apply();
        Intent s = new Intent(this, DnsVpnService.class);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(s); else startService(s);
    }
    void stop() {
        getSharedPreferences("p", 0).edit().putBoolean("enabled", false).apply();
        startService(new Intent(this, DnsVpnService.class).setAction(DnsVpnService.ACTION_STOP));
    }
    @Override protected void onActivityResult(int rq, int rs, Intent d) { if (rq == REQ && rs == RESULT_OK) go(); }
    @Override protected void onResume() { super.onResume(); h.post(tick); }
    @Override protected void onPause() { super.onPause(); h.removeCallbacks(tick); }

    void refresh() {
        boolean on = DnsVpnService.running;
        status.setText(on ? "● PROTEGIDO" : "○ DESATIVADO");
        status.setTextColor(on ? 0xFF3DDC84 : 0xFFFF6B6B);
        btn.setText(on ? "DESATIVAR" : "ATIVAR");
        GradientDrawable g = new GradientDrawable(); g.setCornerRadius(dp(30));
        g.setColor(on ? 0xFFD64545 : 0xFF1E88E5); btn.setBackground(g);
    }
}
