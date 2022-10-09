#include <jni.h>
#include <string>
#include <android/log.h>
#include "m.h"

#define TAG "tais00"
extern "C"
JNIEXPORT jstring JNICALL Java_taisui_enc_1so_M_m(JNIEnv *env, jobject, jstring enc_test) {
    char *str = const_cast<char *>(env->GetStringUTFChars(enc_test, 0));
    for (int i = 0; i < strlen(str); ++i) {
        if (str[i] >= 48 && str[i] <= 57) {
            str[i] = str[i] + 2;
        }
    }
    MD5 md5 = MD5(str);
    std::string md5Result = md5.hexdigest();
    env->ReleaseStringUTFChars(enc_test, str);
    return env->NewStringUTF(md5Result.c_str());

}




