package JAVA;

import android.util.Base64;
import android.util.Log;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Java_crypto {
    private static String TAG = "tais00";
    public static void main(String args) {
        try {
            Log.d(TAG, "AES: " + AES.AES_ENC(args));
            Log.d(TAG, "DES: " + DES.enc(args));
            Log.d(TAG, "DES3: " + DES3.enc(args));
            Log.d(TAG, "HMAC: " + HMAC.hmac_sha1(args));
            Log.d(TAG, "MD5: " + MD5.md5(args));
            Log.d(TAG, "RSA: " + RSA.rsa(args));
            Log.d(TAG, "RSAHex: " + RsaHex.rsaHex(args));
            Log.d(TAG, "MD5 PLUS: " + new Self_MD5().start(args));
        } catch (Exception e) {
            Log.d(TAG, "Enc: " + e);
        }
    }
}

class Utils {
    public static String byteToHexString(byte[] by) {
        StringBuffer SB = new StringBuffer();
        for (int k : by) {
            int j = k;
            if (k < 0) {
                j = k + 256;
            }
            if (j < 16) {
                SB.append("0");
            }
            SB.append(Integer.toHexString(j));
        }
        return SB.toString();
    }

    public static byte[] hexStringToByte(byte[] b) {
        if (b.length % 2 != 0) {
            throw new IllegalArgumentException("长度不是偶数");
        }
        byte[] b2 = new byte[b.length / 2];
        for (int n = 0; n < b.length; n += 2) {
            String item = new String(b, n, 2);
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }
}

class RSA {
    public static String pubKey = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgEYzIqlipFs5mF5M3qVgj/gdYmRV\n" +
            "MIBU53cxcCFjao11svYxmx1EIgLTFVTFETr/cUfpN5L2fONO2ng4zzGUp5dorsmF\n" +
            "Ouavr5fdGfoOc/CU7EFOuGNay+jWHBi07XQbAmnOn26v79s+gkE6qAowjKray/Ca\n" +
            "k7pOitzjO3RcMkDhAgMBAAE=";
    public static String priKey = "MIICWgIBAAKBgEYzIqlipFs5mF5M3qVgj/gdYmRVMIBU53cxcCFjao11svYxmx1E\n" +
            "IgLTFVTFETr/cUfpN5L2fONO2ng4zzGUp5dorsmFOuavr5fdGfoOc/CU7EFOuGNa\n" +
            "y+jWHBi07XQbAmnOn26v79s+gkE6qAowjKray/Cak7pOitzjO3RcMkDhAgMBAAEC\n" +
            "gYApULEmtcp7cjNN1Ln45RL2ePzOhiDMdqvfx7XxwJwWc14HbXyYReAqf2b/hBg2\n" +
            "+94E76pokS9BbMhBl1XCHXZglUyQIWXUUjlxouhLw5N7srkd8M2EqzOAc46E0Qnm\n" +
            "qjK0QjFgBIIZthEttxb+k6VDLUEJJsVEF8kgty7cvlEPrQJBAIZwDEOvgWKdEq1z\n" +
            "0w9vNCUKQaxnocA6xF6V53eKb42kGNaPNAcRYoyJXwV6QU553dbTv+/1fAc1eLu7\n" +
            "duvA00cCQQCFrSNckjNbQDKhpFDnWwX5kHNb9zY9VZcHmJ1O5AZ4PXPyf05yFeWC\n" +
            "cB03bJLwZbuTjiqMYG7J+GibEXFZOk6XAkBBiBjSXZjKQxq5pj35xhE7BPbiXVnB\n" +
            "ZGQYXyYHZVnfR2A8Jm4MC/Nn4gaJmwB+inUSpQForNcahHwntsfPP509AkBhH2qR\n" +
            "16d4pSwkRT6C2Z99s3YdW4ANECKrYjbpGsOYmQ2lItncCgy2uL6BhmE8SK4Ah0pi\n" +
            "s63LELDv+bxhF/wBAkAky9KVW4QS4L/VWgMMf3wElKuD29Mb55Z8oU8E0PIJlOQe\n" +
            "etbu90gQHhypaqeAh7cC+RpcvxXGYW1v5z7kWqsg";

    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes = Base64.decode(key, 0);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes = Base64.decode(key, 0);
        // 这里注意，公钥和私钥的实例化不一样哦
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public static byte[] encrypt(byte[] plaintext) throws Exception {
        PublicKey publicKey = getPublicKey(pubKey);
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        cipher.init(1, publicKey);
        byte[] bt_encrypted = cipher.doFinal(plaintext);
        return bt_encrypted;
    }

    public static byte[] decrypt(byte[] encrypted) throws Exception {
        PrivateKey privateKey = getPrivateKey(priKey);
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        cipher.init(2, privateKey);
        byte[] bt_original = cipher.doFinal(encrypted);
        return bt_original;
    }

    public static String rsa(String args) throws Exception {
        byte[] cipher = encrypt(args.getBytes());
        return Base64.encodeToString(cipher, 0);
    }

    public static final String dec(String arg) throws Exception {
        return new String(decrypt(Base64.decode(arg, 0)));
    }

}

class AES {
    public static String AES_ENC(String args) throws Exception {
        // 生成密钥和 向量
        SecretKeySpec secretKeySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec("0123456789abcdef".getBytes());
        // 初始化
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        // 加密后base64编码 如果是hex的话就16进制转换一下都一样哎
        return Base64.encodeToString(aes.doFinal(args.getBytes(StandardCharsets.UTF_8)), 0);
    }

    public static String AES_DEC(String args) throws Exception {
        // 解密函数部分例子
        SecretKeySpec secretKeySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec("0123456789abcdef".getBytes());
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // 只有初始化传入的模式不一样
        aes.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return new String(aes.doFinal(Base64.decode(args, 0)));
    }

}

class DES {
    public static String enc(String args) throws Exception {

        SecretKey secretKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec("12345678".getBytes()));
        AlgorithmParameterSpec iv = new IvParameterSpec("87654321".getBytes());
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(1, secretKey, iv);
        cipher.update(args.getBytes());
        return Base64.encodeToString(cipher.doFinal(), 0);

    }

}

class DES3 {
    public static final String enc(String arg) throws Exception {
        SecretKey secretKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec("123456781234567812345678".getBytes()));
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(1, secretKey, new IvParameterSpec("12345678".getBytes()));
        return Base64.encodeToString(cipher.doFinal(arg.getBytes()), 0);
    }
}

class HMAC {
    public static String hmac_sha1(String args) throws Exception {
        SecretKey secretKey = new SecretKeySpec("tais00".getBytes(StandardCharsets.UTF_8), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKey);
        mac.update(args.getBytes());
        return Utils.byteToHexString(mac.doFinal("taisui".getBytes()));
    }
}

class MD5 {
    public static String md5(String arg) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(arg.getBytes(StandardCharsets.UTF_8));
        return Utils.byteToHexString(md5.digest());
    }
}

class RsaHex {

    /* renamed from: N */
    public static byte[] f2N = {97, 51, 50, 102, 55, 53, 51, 48, 51, 50, 52, 53, 54, 57, 99, 49, 100, 56, 54, 100, 101, 99, 52, 53, 49, 52, 48, 99, 50, 49, 97, 101, 48, 97, 54, 57, 53, 48, 100, 53, 51, 51, 49, 100, 50, 50, 99, 53, 57, 49, 97, 98, 56, 99, 50, 56, 51, 52, 101, 99, 102, 98, 100, 102, 53, 49, 54, 56, 50, 102, 52, 57, 52, 98, 98, 99, 48, 55, 100, 49, 55, 100, 55, 102, 102, 50, 98, 54, 51, 52, 102, 100, 49, 51, 48, 56, 48, 57, 53, 52, 100, 57, 101, 49, 52, 53, 98, 54, 51, 56, 57, 99, 97, 51, 102, 50, 51, 100, 97, 50, 50, 100, 53, 50, 99, 49, 102, 55, 48, 102, 100, 102, 55, 49, 54, 101, 53, 54, 56, 54, 56, 99, 100, 55, 97, 52, 57, 99, 51, 101, 56, 97, 49, 51, 99, 51, 48, 97, 49, 56, 98, 100, 102, 100, 54, 49, 50, 100, 54, 56, 53, 101, 102, 101, 56, 101, 51, 54, 55, 50, 51, 101, 49, 53, 100, 48, 54, 52, 52, 54, 102, 48, 100, 101, 52, 48, 51, 57, 97, 55, 99, 97, 101, 54, 57, 48, 101, 57, 54, 97, 50, 51, 97, 51, 98, 97, 57, 49, 57, 51, 100, 56, 48, 102, 49, 97, 100, 51, 97, 102, 98, 49, 98, 55, 48, 97, 55, 54, 101, 50, 97, 57, 50, 55, 100, 98, 97, 56, 102, 98, 54, 51, 100, 54, 102, 98};

    /* renamed from: E */
    public static String f1E = "010001";

    public static PublicKey createPublicKey(String stringN, String stringE) throws Exception {
        BigInteger N = new BigInteger(stringN, 16);
        BigInteger E = new BigInteger(stringE, 16);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(N, E);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static byte[] encrypt(String message, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(1, key);
        byte[] data = cipher.doFinal(message.getBytes());
        return data;
    }

    public static String rsaHex(String args) throws Exception {
        return Base64.encodeToString(encrypt(args, createPublicKey(new String(f2N), f1E)), 0);
    }


}

class Self_MD5 {
    //存储小组
    long[] groups = null;
    //存储结果
    String resultMessage = "";

    //四个寄存器的初始向量IV,采用小端存储
    static final long A = 0x67452301L;
    static final long B = 0xefcdab89L;
    static final long C = 0x98badcfeL;
    static final long D = 0x10325476L;

    //java不支持无符号的基本数据(unsigned),所以选用long数据类型
    private long[] result = {A, B, C, D};

    static final long T[][] = {
            {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821},

            {0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a},

            {0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665},

            {0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391}};
    //表示X[k]中的的k取值，决定如何使用消息分组中的字
    static final int k[][] = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12},
            {5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2},
            {0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9}};

    //各次迭代中采用的做循环移位的s值
    static final int S[][] = {
            {7, 12, 17, 22},
            {5, 9, 14, 20},
            {4, 11, 16, 23},
            {6, 10, 15, 21}};

    //4轮循环中使用的生成函数(轮函数)g
    private static long g(int i, long b, long c, long d) {
        switch (i) {
            case 0:
                return (b & c) | ((~b) & d);
            case 1:
                return (b & d) | (c & (~d));
            case 2:
                return b ^ c ^ d;
            case 3:
                return c ^ (b | (~d));
            default:
                return 0;
        }
    }

    //开始使用MD5加密
    public String start(String message) {
        //转化为字节数组
        byte[] inputBytes = message.getBytes();
        //6A 61 6E 6b 69 6e 67
        //获取字节数组的长度
        int byteLen = inputBytes.length;
        //得到K值（以bit作单位的message长度）
        long K = (long) (byteLen << 3);
        //完整小组(512bit)(64byte)的个数
        int groupCount = byteLen / 64;

        //分块
        for (int i = 0; i < groupCount; i++) {
            //每次取512bit
            //处理一个分组
            H(divide(inputBytes, i * 64));
        }

        //填充
        int rest = byteLen % 64;
        //即将填充的一个分组
        byte[] paddingBytes = new byte[64];
        //原来的尾部数据
        for (int i = 0; i < rest; i++)
            paddingBytes[i] = inputBytes[byteLen - rest + i];
        //即小于448bit的情况，先填充100...0再填充K值的低64位
        //此时只会新增一个分组
        if (rest <= 56) {
            //填充100...0
            if (rest < 56) {
                //填充10000000
                paddingBytes[rest] = (byte) (1 << 7);
                //填充00000000
                for (int i = 1; i < 56 - rest; i++)
                    paddingBytes[rest + i] = 0;
            }
            //填充K值低64位
            for (int i = 0; i < 8; i++) {
                paddingBytes[56 + i] = (byte) (K & 0xFFL);
                K = K >> 8;
            }
            //处理分组
            H(divide(paddingBytes, 0));
            //即大于448bit的情况，先填充100...0再填充K值的低64位
            //此时会新增两个分组
        } else {
            //填充10000000
            paddingBytes[rest] = (byte) (1 << 7);
            //填充00000000
            for (int i = rest + 1; i < 64; i++)
                paddingBytes[i] = 0;
            //处理第一个尾部分组
            H(divide(paddingBytes, 0));

            //填充00000000
            for (int i = 0; i < 56; i++)
                paddingBytes[i] = 0;

            //填充低64位
            for (int i = 0; i < 8; i++) {
                //这里很关键，使用小端方式，即Byte数组先存储len的低位数据，然后右移len
                paddingBytes[56 + i] = (byte) (K & 0xFFL);
                K = K >> 8;
            }
            //处理第二个尾部分组
            H(divide(paddingBytes, 0));
        }
        //将Hash值转换成十六进制的字符串
        //小端方式!
        for (int i = 0; i < 4; i++) {
            //解决缺少前置0的问题
            resultMessage += String.format("%02x", result[i] & 0xFF) +
                    String.format("%02x", (result[i] & 0xFF00) >> 8) +
                    String.format("%02x", (result[i] & 0xFF0000) >> 16) +
                    String.format("%02x", (result[i] & 0xFF000000) >> 24);

        }
        return resultMessage;
    }

    //从inputBytes的index开始取512位，作为新的512bit的分组
    private static long[] divide(byte[] inputBytes, int start) {
        //存储一整个分组,就是512bit,数组里每个是32bit，就是4字节，为了消除符号位的影响，所以使用long
        long[] group = new long[16];
        for (int i = 0; i < 16; i++) {
            //每个32bit由4个字节拼接而来
            //小端的从byte数组到bit恢复方法
            group[i] = byte2unsign(inputBytes[4 * i + start]) |
                    (byte2unsign(inputBytes[4 * i + 1 + start])) << 8 |
                    (byte2unsign(inputBytes[4 * i + 2 + start])) << 16 |
                    (byte2unsign(inputBytes[4 * i + 3 + start])) << 24;
        }
        return group;
    }

    //其实byte相当于一个字节的有符号整数，这里不需要符号位，所以把符号位去掉
    public static long byte2unsign(byte b) {
        return b < 0 ? b & 0x7F + 128 : b;
    }

    // groups[] 中每一个分组512位（64字节）
    // MD5压缩函数
    private void H(long[] groups) {
        //缓冲区（寄存器）数组
        long a = result[0], b = result[1], c = result[2], d = result[3];
        //四轮循环
        for (int n = 0; n < 4; n++) {
            //16轮迭代
            for (int i = 0; i < 16; i++) {
                result[0] += (g(n, result[1], result[2], result[3]) & 0xFFFFFFFFL) + groups[k[n][i]] + T[n][i];
                result[0] = result[1] + ((result[0] & 0xFFFFFFFFL) << S[n][i % 4] | ((result[0] & 0xFFFFFFFFL) >>> (32 - S[n][i % 4])));
                //循环轮换
                long temp = result[3];
                result[3] = result[2];
                result[2] = result[1];
                result[1] = result[0];
                result[0] = temp;
            }
        }
        //加入之前计算的结果
        result[0] += a;
        result[1] += b;
        result[2] += c;
        result[3] += d;
        //防止溢出
        for (int n = 0; n < 4; n++) {
            result[n] &= 0xFFFFFFFFL;
        }
    }


}
