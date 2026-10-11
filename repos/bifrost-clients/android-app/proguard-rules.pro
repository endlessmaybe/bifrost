# gomobile resolves generated wrappers/callbacks by name from native code.
# Keep this ABI boundary while R8 optimizes the rest of the application.
-keep class go.** { *; }
-keep class io.nekohasekai.libbox.** { *; }
-keep class com.bifrost.client.BifrostRootRuntimeService { *; }
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
# Tink 1.8 references these compile-time annotations without shipping them.
# None are executable dependencies or accessed reflectively at runtime.
-dontwarn com.google.errorprone.annotations.CanIgnoreReturnValue
-dontwarn com.google.errorprone.annotations.CheckReturnValue
-dontwarn com.google.errorprone.annotations.Immutable
-dontwarn com.google.errorprone.annotations.RestrictedApi
-dontwarn javax.annotation.Nullable
-dontwarn javax.annotation.concurrent.GuardedBy
-keep class com.bifrost.client.BifrostRootSocket { *; }
