package com.hackproff.dnspro;

import android.content.*;
import android.net.VpnService;
import android.os.Build;

/** Recebe: boot, atualização do app e watchdog (a cada ~2 min). Religa a VPN se estiver caída. */
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        boolean on = c.getSharedPreferences("p", 0).getBoolean("enabled", true);
        if (!on || DnsVpnService.running || VpnService.prepare(c) != null) return;
        Intent s = new Intent(c, DnsVpnService.class);
        if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(s); else c.startService(s);
    }
}
