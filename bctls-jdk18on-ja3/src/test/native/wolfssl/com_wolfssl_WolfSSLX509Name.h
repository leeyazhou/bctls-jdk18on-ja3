/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_wolfssl_WolfSSLX509Name */

#ifndef _Included_com_wolfssl_WolfSSLX509Name
#define _Included_com_wolfssl_WolfSSLX509Name
#ifdef __cplusplus
extern "C" {
#endif
#undef com_wolfssl_WolfSSLX509Name_MBSTRING_UTF8
#define com_wolfssl_WolfSSLX509Name_MBSTRING_UTF8 256L
/*
 * Class:     com_wolfssl_WolfSSLX509Name
 * Method:    X509_NAME_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLX509Name_X509_1NAME_1new
  (JNIEnv *, jclass);

/*
 * Class:     com_wolfssl_WolfSSLX509Name
 * Method:    X509_NAME_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLX509Name_X509_1NAME_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     com_wolfssl_WolfSSLX509Name
 * Method:    X509_NAME_add_entry_by_txt
 * Signature: (JLjava/lang/String;I[BIII)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLX509Name_X509_1NAME_1add_1entry_1by_1txt
  (JNIEnv *, jclass, jlong, jstring, jint, jbyteArray, jint, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
