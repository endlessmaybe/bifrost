#include <jni.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bifrost_root_mark.h"

// Preserve Android's netId/interface selection and mark only our sockets.
// Called only for descriptors owned by this root runtime, before connect().
extern "C" JNIEXPORT jboolean JNICALL
Java_com_bifrost_client_BifrostRootSocket_protect(JNIEnv*, jobject, jint fd) {
    if (getuid() != 0 || fd < 0) return JNI_FALSE;
    unsigned mark = 0;
    socklen_t size = sizeof(mark);
    if (getsockopt(fd, SOL_SOCKET, SO_MARK, &mark, &size) != 0) return JNI_FALSE;
    mark |= ANDROID_PROTECTED_FROM_VPN | BIFROST_ROOT_SOCKET_MARK;
    return setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) == 0 ? JNI_TRUE : JNI_FALSE;
}

#include "bifrost_connection_owner.h"
// The root core already has /proc access. Do not queue new connections behind
// the helper's iptables health checks on its single control socket.
extern "C" JNIEXPORT jint JNICALL
Java_com_bifrost_client_BifrostRootSocket_owner(JNIEnv* env, jobject, jint protocol,
    jstring source, jint sourcePort, jstring target, jint targetPort) {
    if (getuid() != 0 || !source || !target) return -1;
    const char* a = env->GetStringUTFChars(source, nullptr);
    if (!a) return -1;
    std::string from(a); env->ReleaseStringUTFChars(source, a);
    const char* b = env->GetStringUTFChars(target, nullptr);
    if (!b) return -1;
    std::string to(b); env->ReleaseStringUTFChars(target, b);
    try {
        const auto result = bifrost_owner::connection_owner("OWNER " + std::to_string(protocol) + " " + from + " " +
            std::to_string(sourcePort) + " " + to + " " + std::to_string(targetPort));
        return std::stoi(result.substr(4));
    } catch (...) { return -1; }
}
