package com.yangwenbo.cipherspeed;

import android.annotation.SuppressLint;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final TextView tv = (TextView) findViewById(R.id.console);
        tv.append("# Speed Test of 10MB Random Bytes Enc/Decryption #\n");
        @SuppressLint("HandlerLeak") final Handler log_handle = new Handler(){
            @Override
            public void handleMessage(Message msg) {
                tv.append((String)msg.obj);
            }
        };
        new Thread(new Runnable() {
            @Override
            public void run() {
                CipherBenchmark benchmark = new CipherBenchmark(log_handle);
                benchmark.runtest();
            }
        }).start();
    }
}