package com.hackproff.dnspro;

import android.app.*;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.concurrent.*;

/** VPN local que só captura DNS e encaminha ao AdGuard DNS (bloqueio de anúncios/rastreadores). */
public class DnsVpnService extends VpnService {
    public static final String ACTION_STOP = "com.hackproff.dnspro.STOP";
    public static volatile boolean running = false;
    static final String FAKE_DNS = "10.111.222.1";
    static final String[] UPSTREAM = {"94.140.14.14", "94.140.15.15"}; // AdGuard DNS
    private ParcelFileDescriptor tun;
    private ExecutorService pool;
    private Thread loop;

    @Override public int onStartCommand(Intent i, int f, int id) {
        if (i != null && ACTION_STOP.equals(i.getAction())) { stopVpn(); stopSelf(); return START_NOT_STICKY; }
        startFg();
        if (!running) startVpn();
        return START_STICKY;
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

    private void startVpn() {
        try {
            tun = new Builder().setSession("DNSPRO").addAddress("10.111.222.2", 32)
                    .addDnsServer(FAKE_DNS).addRoute(FAKE_DNS, 32).setMtu(1500).establish();
        } catch (Exception e) { tun = null; }
        if (tun == null) { stopSelf(); return; }
        running = true;
        pool = Executors.newFixedThreadPool(8);
        final ParcelFileDescriptor fd = tun;
        loop = new Thread(new Runnable() { public void run() { runLoop(fd); } });
        loop.start();
    }

    private void runLoop(ParcelFileDescriptor fd) {
        final FileInputStream in = new FileInputStream(fd.getFileDescriptor());
        final FileOutputStream out = new FileOutputStream(fd.getFileDescriptor());
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
                if (plen <= 0) continue;
                final byte[] q = Arrays.copyOfRange(b, ihl + 8, ihl + 8 + plen);
                final byte[] src = Arrays.copyOfRange(b, 12, 16), dst = Arrays.copyOfRange(b, 16, 20);
                pool.execute(new Runnable() { public void run() { answer(q, src, dst, sport, out); } });
            }
        } catch (Exception e) { /* fechado */ }
    }

    private void answer(byte[] q, byte[] src, byte[] dst, int sport, FileOutputStream out) {
        byte[] r = null;
        for (String h : UPSTREAM) {
            DatagramSocket s = null;
            try {
                s = new DatagramSocket();
                protect(s); // evita loop dentro da própria VPN
                s.setSoTimeout(3000);
                s.send(new DatagramPacket(q, q.length, InetAddress.getByName(h), 53));
                byte[] buf = new byte[4096];
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                s.receive(p);
                r = Arrays.copyOf(buf, p.getLength());
                break;
            } catch (Exception e) { /* tenta o secundário */ }
            finally { if (s != null) s.close(); }
        }
        if (r == null || r.length + 28 > 1500) return;
        int tot = 28 + r.length;
        byte[] p = new byte[tot];
        p[0] = 0x45; p[2] = (byte) (tot >> 8); p[3] = (byte) tot; p[8] = 64; p[9] = 17;
        System.arraycopy(dst, 0, p, 12, 4);
        System.arraycopy(src, 0, p, 16, 4);
        int c = csum(p, 0, 20); p[10] = (byte) (c >> 8); p[11] = (byte) c;
        p[21] = 53; p[22] = (byte) (sport >> 8); p[23] = (byte) sport;
        int ul = 8 + r.length; p[24] = (byte) (ul >> 8); p[25] = (byte) ul;
        System.arraycopy(r, 0, p, 28, r.length);
        try { synchronized (out) { out.write(p); } } catch (IOException e) { }
    }

    static int csum(byte[] b, int off, int len) {
        long s = 0;
        for (int i = 0; i < len; i += 2) s += ((b[off + i] & 0xff) << 8) | ((i + 1 < len) ? (b[off + i + 1] & 0xff) : 0);
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s & 0xffff);
    }

    private void stopVpn() {
        running = false;
        try { if (tun != null) tun.close(); } catch (IOException e) { }
        tun = null;
        if (pool != null) pool.shutdownNow();
        if (loop != null) loop.interrupt();
        stopForeground(true);
    }

    @Override public void onRevoke() {
        getSharedPreferences("p", 0).edit().putBoolean("enabled", false).apply();
        stopVpn(); stopSelf();
    }
    @Override public void onDestroy() { stopVpn(); super.onDestroy(); }
}
