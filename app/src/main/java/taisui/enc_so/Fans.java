package taisui.enc_so;

public class Fans {
    public static int a;

    public Fans(int x){
        a = x;
    }
    public static int add(int x){
        a += x;
        return a;
    }

    public static int geta() {
        return a;
    }
}
