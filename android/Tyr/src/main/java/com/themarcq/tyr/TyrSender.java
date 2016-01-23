package com.themarcq.tyr;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.IBinder;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Base64;
import android.util.Log;

import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;

import javax.crypto.Cipher;


public class TyrSender extends NotificationListenerService {

    private String phoneName;
    ArrayList<desktop> desktopListArrays = new ArrayList<>();
    private NLServiceReceiver nlservicereciver;
    private String TAG = this.getClass().getSimpleName();
    private DatagramSocket socket;

    @Override
    public void onCreate() {
        super.onCreate();

        loadConfiguration();

        try {
            socket = new DatagramSocket(null);
        } catch (Exception e) {
            Log.i(TAG,e.toString());
        }
        if(socket != null) {
            nlservicereciver = new NLServiceReceiver();
            IntentFilter filter = new IntentFilter();
            filter.addAction("com.themarcq.tyr.NOTIFICATION_LISTENER_SERVICE");
            registerReceiver(nlservicereciver, filter);

            pingTimerTask pingTask = new pingTimerTask();
            Timer pingTimer = new Timer();
            pingTimer.schedule(pingTask, 0, 3000);

            new receivePackets().execute();
        }
    }

    class pingTimerTask extends TimerTask {
        public void run() {
            for (desktop d:desktopListArrays) {
                long now = System.currentTimeMillis();
                if (now-d.lastPing>9000) {
                    packet pkt = new packet();
                    pkt.type = 'i';
                    pkt.error = 0;
                    pkt.length = 4;
                    pkt.buf = new byte[4];
                    pkt.buf[0] = (byte) (d.id);
                    pkt.buf[1] = (byte) (d.id >> 8);
                    pkt.buf[2] = (byte) (d.id >> 16);
                    pkt.buf[3] = (byte) (d.id >> 24);
                    byte[] buf = pkt.exportBuffer();
                    try {
                        InetAddress trackAddr = InetAddress.getByName(d.serverAddress);
                        DatagramPacket p = new DatagramPacket(buf, buf.length, trackAddr, d.serverPort);
                        socket.send(p);
                    } catch (Exception e) {
                        Log.i("TAG", e.toString());
                    }
                } else {
                    packet pkt = new packet();
                    pkt.type = 'p';
                    pkt.error = '\0';
                    pkt.length = 4;
                    pkt.buf = new byte[4];
                    pkt.buf[0] = (byte) (d.id >> 24);
                    pkt.buf[1] = (byte) (d.id >> 16);
                    pkt.buf[2] = (byte) (d.id >> 8);
                    pkt.buf[3] = (byte) (d.id);
                    byte[] buf = pkt.exportBuffer();

                    try {
                        InetAddress peerAddr = InetAddress.getByName(d.address);
                        DatagramPacket p = new DatagramPacket(buf, buf.length, peerAddr, d.port);
                        socket.send(p);
                    } catch (Exception e) {
                        Log.i("TAG", e.toString());
                    }
                }
            }
        }
    }

    private class receivePackets extends AsyncTask<Void, Void, Void> {

        @Override
        protected Void doInBackground(Void... arg0) {
            for(;;) {
                byte[] buf = new byte[1050];
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    socket.receive(p);
                } catch (Exception e) {
                    Log.i(TAG, "Can't receive from socket with exception: " + e.toString());
                }
                packet pkt = new packet();
                byte[] lol = p.getData();
                pkt.importBuffer(p.getData());
                int id=0;
                switch (pkt.type) {
                    case 'r':
                        for (desktop d : desktopListArrays) {
                            int id1 = ((int) pkt.buf[0]) & 0xFF;
                            int id2 = ((int) pkt.buf[1] << 8) & 0xFF00;
                            int id3 = ((int) pkt.buf[2] << 16) & 0xFF0000;
                            int id4 = ((int) pkt.buf[3] << 24) & 0xFF000000;
                            id = id1 | id2 | id3 | id4;
                            if (d.id == id) {
                                d.lastPing = System.currentTimeMillis();
                            }
                        }
                        break;
                    case 'p':
                        break;
                    case 'i':
                        if (pkt.error == '\0') {
                            int id1 = ((int) pkt.buf[0]) & 0xFF;
                            int id2 = ((int) pkt.buf[1] << 8) & 0xFF00;
                            int id3 = ((int) pkt.buf[2] << 16) & 0xFF0000;
                            int id4 = ((int) pkt.buf[3] << 24) & 0xFF000000;
                            id = id1 | id2 | id3 | id4;
                            int[] ip_int = new int[4];
                            ip_int[0] = ((int)pkt.buf[4])&0xFF;
                            ip_int[1] = ((int)pkt.buf[5])&0xFF;
                            ip_int[2] = ((int)pkt.buf[6])&0xFF;
                            ip_int[3] = ((int)pkt.buf[7])&0xFF;

                            String ip = ip_int[0] + "." + ip_int[1] + "." + ip_int[2] + "." + ip_int[3];
                            int port = ((int)pkt.buf[8]<<8)&0xFF00 | ((int)pkt.buf[9])&0xFF;
                            for (desktop d : desktopListArrays) {
                                if (d.id == id) {
                                    d.address = ip;
                                    d.port = port;
                                    d.lastPing = System.currentTimeMillis();
                                }
                            }
                        } else {
                            Log.i(TAG, "There is no such id in tracker");
                        }
                        break;
                }
            }
        }

        private String intToIp(int i) {
            return ((i >> 24 ) & 0xFF) + "." +
                    ((i >> 16 ) & 0xFF) + "." +
                    ((i >> 8 ) & 0xFF) + "." +
                    ( i & 0xFF);

        }
    }

    public class packet {
        char type;
        char error;
        int length;
        byte[] buf;

        public void importBuffer(byte[] buffer) {
            type=(char)buffer[0];
            error=(char)buffer[1];
            length=(int)buffer[2];
            length=(length<<8) | (int)buffer[3];
            length=(length<<8) | (int)buffer[4];
            length=(length<<8) | (int)buffer[5];
            buf = new byte[length];
            for(int i=0;i<length; i++) {
                buf[i]=buffer[i+6];
            }
        }

        public byte[] exportBuffer() {
            byte[] b = new byte[this.length+6];
            b[0] = (byte)type;
            b[1] = (byte)error;
            b[2] = (byte)(length>>24);
            b[3] = (byte)(length>>16);
            b[4] = (byte)(length>>8);
            b[5] = (byte)(length);
            for(int i=0; i<length; i++) {
                b[i+6] = buf[i];
            }
            return b;
        }
    }

    private void loadConfiguration() {
        SharedPreferences settings = getApplicationContext().getSharedPreferences("TyrPrefs", getApplicationContext().MODE_PRIVATE);
        phoneName = settings.getString("phoneName", "Phone");
        String desktopList = settings.getString("desktopList", "");
        String[] desktopListArray = desktopList.split("@");
        desktopListArrays.clear();
        for(int i=0; i < desktopListArray.length; i++) {
            String[] s = desktopListArray[i].split(";");
            if(s.length>3) {
                desktop d = new desktop(s);
                desktopListArrays.add(d);
            }
        }
    }

    private class desktop {
        PublicKey key;
        int id;
        String serverAddress;
        int serverPort;
        long lastPing;
        String address;
        int port;

        public desktop (String[] s) {
            this.id = Integer.parseInt(s[1]);
            this.serverAddress = s[4];
            this.serverPort = Integer.parseInt(s[5]);
            this.lastPing = 0;
            try {
                byte[] eBytes = Base64.decode(s[2], Base64.DEFAULT);
                byte[] nBytes = Base64.decode(s[3], Base64.DEFAULT);
                BigInteger n =new BigInteger(1,nBytes);
                BigInteger e =new BigInteger(1,eBytes);
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(e, n);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                key = keyFactory.generatePublic(keySpec);
            } catch (Exception e) {
                Log.d(TAG,"************");
                Log.d(TAG,e.toString());
                Log.d(TAG,s[2]);
            }
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        unregisterReceiver(nlservicereciver);
    }

    @Override
    public void onListenerConnected() {
        Log.i(TAG, "Got onListenerConnected");
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        Log.d(TAG, "**********  onNotificationPosted");
        Log.d(TAG, "ID :" + sbn.getId() + "\t" + sbn.getNotification().tickerText + "\t" + sbn.getPackageName());
        for (desktop d:desktopListArrays) {
            try {
                Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, d.key);
                byte[] cipherData = cipher.doFinal(sbn.getNotification().tickerText.toString().getBytes()g);
                InetAddress peerAddr = InetAddress.getByName(d.address);
                packet pkt = new packet();
                pkt.type = 'n';
                pkt.error = '\0';
                pkt.length = cipherData.length;
                pkt.buf = cipherData;
                byte[] buf = pkt.exportBuffer();
                String s="";
                for(int i=0;i<30;i++)
                    s=s+buf[i]+" ";
                Log.d(TAG,s);
                Log.d(TAG, d.address + " " + d.port);
                DatagramPacket p = new DatagramPacket(buf, buf.length, peerAddr, d.port);
                socket.send(p);
            } catch (Exception e) {
                Log.i("TAG", e.toString());
            }
        }
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
    }

    @Override
    public IBinder onBind(Intent  intent) {
        return super.onBind(intent);
    }

    class NLServiceReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            if(intent.getStringExtra("command").equals("list")){
                int i=1;
                try {
                    for (StatusBarNotification sbn : TyrSender.this.getActiveNotifications()) {
                        Intent i2 = new Intent("com.themarcq.tyr.NOTIFICATION_LISTENER");
                        i2.putExtra("notification_event", i + " " + sbn.getPackageName() + "\n");
                        sendBroadcast(i2);
                        i++;
                    }
                } catch (Exception e) {
                    Log.i(TAG,e.toString());
                }
            }
            else if(intent.getStringExtra("command").equals("reloadconfig")) {
                Log.d(TAG,"reloading");
                loadConfiguration();
            }
        }
    }
}