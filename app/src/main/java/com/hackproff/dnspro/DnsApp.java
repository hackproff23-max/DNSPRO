package com.hackproff.dnspro;

import android.app.*;
import android.content.Intent;
import android.os.SystemClock;

/** Se o app der crash, agenda reinício automático em 2s. */
public class DnsApp extends Application {
    @Override public void onCreate() {
        super.onCreate();
        final Thread.UncaughtExceptionHandler old = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            public void uncaughtException(Thread t, Throwable e) {
                try {
                    AlarmManager am = (AlarmManager) getSystemService(ALARM_SERVICE);
                    am.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + 2000,
                        PendingIntent.getBroadcast(DnsApp.this, 8,
                            new Intent(DnsApp.this, BootReceiver.class).setAction(DnsVpnService.ACTION_WATCHDOG),
                            PendingIntent.FLAG_UPDATE_CURRENT));
                } catch (Throwable x) { }
                if (old != null) old.uncaughtException(t, e); else System.exit(1);
            }
        });
    }
}
