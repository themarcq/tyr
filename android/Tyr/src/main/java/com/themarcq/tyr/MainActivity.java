package com.themarcq.tyr;

import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.Uri;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    private NotificationReceiver nReceiver;
    private String TAG = this.getClass().getSimpleName();
    final Context context = this;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(com.themarcq.tyr.R.layout.activity_main);

        final Button button = (Button) findViewById(com.themarcq.tyr.R.id.ScanQrcodeButton);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                scanQrcode();
            }
        });
        try {
            final Button button2 = (Button) findViewById(com.themarcq.tyr.R.id.DebugButton);
            button2.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    Intent i = new Intent("com.themarcq.tyr.NOTIFICATION_LISTENER_SERVICE");
                    i.putExtra("command", "list");
                    sendBroadcast(i);
                }
            });
        } catch (Exception e) {
            Log.i(TAG, e.toString());
        }

        final EditText text = (EditText) findViewById(com.themarcq.tyr.R.id.phoneName);
        text.addTextChangedListener(new TextWatcher() {
            public void afterTextChanged(Editable s) {
                SharedPreferences settings = getSharedPreferences("TyrPrefs", getApplicationContext().MODE_PRIVATE);
                SharedPreferences.Editor editor = settings.edit();
                editor.putString("phoneName", text.getText().toString());
                editor.commit();
            }

            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }
        });

        final ListView List = (ListView) findViewById(R.id.listView);
        List.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(AdapterView<?> parent, View view, int position, long id) {
                AlertDialog.Builder builder = new AlertDialog.Builder(context);
// Add the buttons
                final int pos = position;
                builder.setPositiveButton("ok", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        listRemove(pos);
                        serviceRestart();
                        fillList();
                    }
                });
                builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        //:(
                    }
                });
                builder.setMessage("Do you want to delete this entry?")
                        .setTitle("Entry delete");

                AlertDialog dialog = builder.create();
                try {
                    dialog.show();
                } catch (Exception e) {
                    Log.d(TAG, e.toString());
                }
                return true;
            }
        });

        fillList();
        serviceRestart();

        nReceiver = new NotificationReceiver();
        IntentFilter filter = new IntentFilter();
        filter.addAction("com.themarcq.tyr.NOTIFICATION_LISTENER");
        registerReceiver(nReceiver,filter);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(nReceiver);
    }

    public void fillList() {
        SharedPreferences settings = getSharedPreferences("TyrPrefs", getApplicationContext().MODE_PRIVATE);
        String phoneName = settings.getString("phoneName", "Phone");
        String desktopList = settings.getString("desktopList", "");
        String[] desktopListArray = desktopList.split("@");

        TextView t=(TextView)findViewById(com.themarcq.tyr.R.id.phoneName);
        t.setText(phoneName);

        final ListView list = (ListView) findViewById(com.themarcq.tyr.R.id.listView);
        final ArrayAdapter<String> adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, desktopListArray);
        list.setAdapter(adapter);
    }

    public void listRemove(int pos) {
        SharedPreferences settings = getSharedPreferences("TyrPrefs", getApplicationContext().MODE_PRIVATE);
        String desktopList = settings.getString("desktopList", "");
        String[] desktopListArray = desktopList.split("@");
        String newDesktopList = "";

        for(int i=0; i<desktopListArray.length; i++)
            if(i!=pos)
                newDesktopList = newDesktopList + desktopListArray[i] + "@";

        SharedPreferences.Editor editor = settings.edit();
        editor.putString("desktopList", newDesktopList);
        editor.commit();
    }

    public void listAdd(String data) {
        SharedPreferences settings = getSharedPreferences("TyrPrefs", getApplicationContext().MODE_PRIVATE);
        String desktopList = settings.getString("desktopList", "");

        desktopList = desktopList+ data + "@" ;

        SharedPreferences.Editor editor = settings.edit();
        editor.putString("desktopList", desktopList);
        editor.commit();
    }

    public void serviceRestart() {
        Intent i = new Intent("com.themarcq.tyr.NOTIFICATION_LISTENER_SERVICE");
        i.putExtra("command", "reloadconfig");
        sendBroadcast(i);
    }

    private void scanQrcode() {
        try {
            Intent intent = new Intent("com.google.zxing.client.android.SCAN");
            intent.putExtra("SCAN_MODE", "QR_CODE_MODE");//for Qr code, its "QR_CODE_MODE" instead of "PRODUCT_MODE"
            intent.putExtra("SAVE_HISTORY", false);//this stops saving ur barcode in barcode scanner app's history
            startActivityForResult(intent, 0);
        } catch (Exception e) {
            Toast.makeText(getApplicationContext(), "No QR scanner. Install this one.", Toast.LENGTH_SHORT).show();
            Uri marketUri = Uri.parse("market://details?id=com.google.zxing.client.android");
            Intent marketIntent = new Intent(Intent.ACTION_VIEW,marketUri);
            startActivity(marketIntent);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 0) {
            if (resultCode == RESULT_OK) {
                String contents = data.getStringExtra("SCAN_RESULT"); //this is the result
                if (contents.matches("^Tyr;(.*)")) {
                    listAdd(contents);
                } else {
                    Toast.makeText(getApplicationContext(), "Invalid QR code" + contents, Toast.LENGTH_SHORT).show();
                }
                serviceRestart();
                fillList();
            }
        }
    }

    class NotificationReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            Toast.makeText(getApplicationContext(),
                    intent.getStringExtra("notification_event") + "\n",
                    Toast.LENGTH_SHORT).show();
        }
    }
}
