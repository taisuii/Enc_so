package taisui.enc_so;

import android.content.Context;
import android.util.Log;
import android.view.View;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import taisui.enc_so.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {
    public static Context con;
    private static TextView t;
    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        t = binding.sampleText;
        con = this;
    }

    public static void m(View view) {
        s(new M().m(g()));
    }


    public static String g() {
        return new StringBuilder("Wecat_tais00_").append(System.currentTimeMillis()).toString();
    }

    public static void s(String args) {
        t.setText(args);
    }

}

class M {
    {
        System.loadLibrary("_wx_taisui00");
    }

    public native String m(String tais00);

}

class TOAST {
    public static void t(String args) {
        Toast.makeText(MainActivity.con, args, Toast.LENGTH_SHORT).show();
    }
}
