package taisui.enc_so;

import android.content.Context;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import taisui.enc_so.databinding.ActivityMainBinding;
import JAVA.Java_crypto;

public class MainActivity extends AppCompatActivity {
    private static String TAG = "tais00";
    public static Context con;
    private static TextView t;
    private static TextView t2;
    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        t = binding.sampleText;
        t2 = binding.sampleText2;
        con = this;
    }


    public static void m(View view) {
        String raw = g();
        String result = new M().m(raw);
        s(raw);
        s2(result);
    }

    public static void j(View view) {
        Java_crypto.main(g());
        s("Java_crypto on Android Logcat of TAG 'tais00'");
    }


    public static String g() {
        return new StringBuilder("Wecat_tais00_").append(System.currentTimeMillis()).toString();
    }

    public static void s(String args) {
        Log.d(TAG, "Raw: " + args);
        t.setText("Raw: " + args);
    }

    public static void s2(String args) {
        Log.d(TAG, "Enc result: " + args);
        t2.setText("Enc result: " + args);
    }
}


class M {
    {
        System.loadLibrary("_wx_taisui00");
    }

    public native String m(String tais00);

}


class T {
    public static void t(String args) {
        Toast.makeText(MainActivity.con, args, Toast.LENGTH_SHORT).show();
    }
}
