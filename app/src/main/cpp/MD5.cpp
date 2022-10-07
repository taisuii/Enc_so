#include <jni.h>
#include <string>

extern "C"
JNIEXPORT jstring JNICALL Java_taisui_enc_1so_M_m(JNIEnv* env,jobject,jstring enc_test) {
    const char *str = env->GetStringUTFChars(enc_test, 0);
    env->ReleaseStringUTFChars(enc_test, str);
    printf("123");
    return env->NewStringUTF(str);
}

