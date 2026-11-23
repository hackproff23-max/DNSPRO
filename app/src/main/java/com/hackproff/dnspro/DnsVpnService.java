package com.hackproff.dnspro;

import android.app.*;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** VPN local de DNS: cache + consulta paralela ao AdGuard DNS + auto-recuperação. */
public class DnsVpnService extends VpnService {
    public static final String ACTION_STOP = "com.hackproff.dnspro.STOP";
    public static final String ACTION_WATCHDOG = "com.hackproff.dnspro.WATCHDOG";
    public static volatile boolean running = false;
    static final String FAKE_DNS = "10.111.222.1";
    static final String[] UPSTREAM = {"94.140.14.14", "94.140.15.15"}; // AdGuard DNS

    static class Entry { byte[] r; long exp; }
    private final ConcurrentHashMap<String, Entry> cache = new ConcurrentHashMap<String, Entry>();
    private final AtomicInteger fails = new AtomicInteger();
    private volatile boolean restarting;
    private ParcelFileDescriptor tun;
    private ExecutorService pool;
    private Thread loop;

    @Override public int onStartCommand(Intent i, int f, int id) {
        if (i != null && ACTION_STOP.equals(i.getAction())) { stopVpn(); stopSelf(); return START_NOT_STICKY; }
        startFg();
        scheduleWatchdog();
        if (!running) startVpn();
        return START_STICKY;
    }

    private PendingIntent wdIntent() {
        return PendingIntent.getBroadcast(this, 7, new Intent(this, BootReceiver.class).setAction(ACTION_WATCHDOG),
                PendingIntent.FLAG_UPDATE_CURRENT);
    }
    private void scheduleWatchdog() {
        AlarmManager am = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
        am.setInexactRepeating(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + 60000, 120000, wdIntent());
    }

    private void startFg() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(new NotificationChannel("dnspro", "DNSPRO", NotificationManager.IMPORTANCE_MIN));
            b = new Notification.Builder(this, "dnspro");
        } else { b = new Notification.Builder(this); b.setPriority(Notification.PRIORITY_MIN); }
        b.setContentTitle("DNSPRO ativo").setContentText("Bloqueio de anúncios AdGuard DNS")
         .setSmallIcon(android.R.drawable.ic_lock_lock)
         .setContentIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), 0));
        startForeground(1, b.build());
    }

    private synchronized void startVpn() {
        try {
            tun = new Builder().setSession("DNSPRO").addAddress("10.111.222.2", 32)
                    .addDnsServer(FAKE_DNS).addRoute(FAKE_DNS, 32).setMtu(1500).establish();
        } catch (Exception e) { tun = null; }
        if (tun == null) { running = false; return; } // o watchdog tenta de novo
        running = true;
        fails.set(0);
        pool = Executors.newFixedThreadPool(8);
        final ParcelFileDescriptor fd = tun;
        loop = new Thread(new Runnable() { public void run() { runLoop(fd); } });
        loop.start();
    }

    private synchronized void stopTunnel() {
        running = false;
        try { if (tun != null) tun.close(); } catch (IOException e) { }
        tun = null;
        if (pool != null) pool.shutdownNow();
        if (loop != null) loop.interrupt();
    }

    /** DNS parou de responder: derruba e recria o túnel sozinho. */
    private void restartTunnel() {
        if (restarting) return;
        restarting = true;
        new Thread(new Runnable() { public void run() {
            try {
                stopTunnel();
                Thread.sleep(1500);
                if (getSharedPreferences("p", 0).getBoolean("enabled", true)) startVpn();
            } catch (Exception e) { }
            restarting = false;
        } }).start();
    }

    private void runLoop(ParcelFileDescriptor fd) {
        final FileInputStream in = new FileInputStream(fd.getFileDescriptor());
        final FileOutputStream out = new FileOutputStream(fd.getFileDescriptor());
        final ExecutorService ex = pool;
        byte[] b = new byte[32767];
        try {
            while (running) {
                int n = in.read(b);
                if (n < 0) break;
                if (n < 28 || (b[0] >> 4) != 4) continue;
                int ihl = (b[0] & 0xF) * 4;
                if (b[9] != 17 || n < ihl + 8) continue;
                int dport = ((b[ihl + 2] & 0xff) << 8) | (b[ihl + 3] & 0xff);
                if (dport != 53) continue;
                final int sport = ((b[ihl] & 0xff) << 8) | (b[ihl + 1] & 0xff);
                int ulen = ((b[ihl + 4] & 0xff) << 8) | (b[ihl + 5] & 0xff);
                int plen = Math.min(ulen - 8, n - ihl - 8);
                if (plen <= 12) continue;
                final byte[] q = Arrays.copyOfRange(b, ihl + 8, ihl + 8 + plen);
                final byte[] src = Arrays.copyOfRange(b, 12, 16), dst = Arrays.copyOfRange(b, 16, 20);
                ex.execute(new Runnable() { public void run() { answer(q, src, dst, sport, out); } });
            }
        } catch (Exception e) { /* túnel fechado */ }
    }

    private byte[] resolve(byte[] q) {
        DatagramSocket s = null;
        try {
            s = new DatagramSocket();
            protect(s);
            s.setSoTimeout(2500);
            for (String h : UPSTREAM) s.send(new DatagramPacket(q, q.length, InetAddress.getByName(h), 53)); // corrida: vence o mais rápido
            byte[] buf = new byte[4096];
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            s.receive(p);
            return Arrays.copyOf(buf, p.getLength());
        } catch (Exception e) { return null; }
        finally { if (s != null) s.close(); }
    }

    private void answer(byte[] q, byte[] src, byte[] dst, int sport, FileOutputStream out) {
        String key = new String(q, 2, q.length - 2, java.nio.charset.Charset.forName("ISO-8859-1"));
        byte[] r = null;
        Entry e = cache.get(key);
        if (e != null && e.exp > System.currentTimeMillis()) {
            r = e.r.clone(); r[0] = q[0]; r[1] = q[1];
        } else {
            r = resolve(q);
            if (r == null) r = resolve(q);
            if (r == null || r.length < 12) {
                if (fails.incrementAndGet() >= 6) restartTunnel();
                return;
            }
            fails.set(0);
            int rc = r[3] & 0xf;
            if ((rc == 0 || rc == 3) && (r[2] & 0x02) == 0) {
                int ttl = Math.max(20, Math.min(minTtl(r), 3600));
                if (cache.size() > 3000) cache.clear();
                Entry n = new Entry(); n.r = r; n.exp = System.currentTimeMillis() + ttl * 1000L;
                cache.put(key, n);
            }
        }
        if (r.length + 28 > 1500) return;
        int tot = 28 + r.length;
        byte[] p = new byte[tot];
        p[0] = 0x45; p[2] = (byte) (tot >> 8); p[3] = (byte) tot; p[8] = 64; p[9] = 17;
        System.arraycopy(dst, 0, p, 12, 4);
        System.arraycopy(src, 0, p, 16, 4);
        int c = csum(p, 0, 20); p[10] = (byte) (c >> 8); p[11] = (byte) c;
        p[21] = 53; p[22] = (byte) (sport >> 8); p[23] = (byte) sport;
        int ul = 8 + r.length; p[24] = (byte) (ul >> 8); p[25] = (byte) ul;
        System.arraycopy(r, 0, p, 28, r.length);
        try { synchronized (out) { out.write(p); } } catch (IOException x) { }
    }

    static int minTtl(byte[] r) {
        try {
            int qd = ((r[4] & 0xff) << 8) | (r[5] & 0xff);
            int rr = (((r[6] & 0xff) << 8) | (r[7] & 0xff)) + (((r[8] & 0xff) << 8) | (r[9] & 0xff));
            int p = 12;
            for (int i = 0; i < qd; i++) p = skipName(r, p) + 4;
            int min = Integer.MAX_VALUE;
            for (int i = 0; i < rr; i++) {
                p = skipName(r, p);
                int ttl = ((r[p + 4] & 0xff) << 24) | ((r[p + 5] & 0xff) << 16) | ((r[p + 6] & 0xff) << 8) | (r[p + 7] & 0xff);
                int rd = ((r[p + 8] & 0xff) << 8) | (r[p + 9] & 0xff);
                if (ttl >= 0 && ttl < min) min = ttl;
                p += 10 + rd;
            }
            return min == Integer.MAX_VALUE ? 60 : min;
        } catch (Exception e) { return 20; }
    }
    static int skipName(byte[] r, int p) {
        while (true) {
            int l = r[p] & 0xff;
            if (l == 0) return p + 1;
            if ((l & 0xC0) == 0xC0) return p + 2;
            p += l + 1;
        }
    }

    static int csum(byte[] b, int off, int len) {
        long s = 0;
        for (int i = 0; i < len; i += 2) s += ((b[off + i] & 0xff) << 8) | ((i + 1 < len) ? (b[off + i + 1] & 0xff) : 0);
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s & 0xffff);
    }

    private void stopVpn() {
        ((AlarmManager) getSystemService(Context.ALARM_SERVICE)).cancel(wdIntent());
        stopTunnel();
        stopForeground(true);
    }

    @Override public void onRevoke() {
        getSharedPreferences("p", 0).edit().putBoolean("enabled", false).apply();
        stopVpn(); stopSelf();
    }
    @Override public void onDestroy() { stopTunnel(); super.onDestroy(); }
}
