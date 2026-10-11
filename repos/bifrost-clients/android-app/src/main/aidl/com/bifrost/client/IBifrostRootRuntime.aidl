package com.bifrost.client;

import android.os.Bundle;
import android.os.ParcelFileDescriptor;

// Large verified configurations travel through a bounded pipe, never a Binder
// transaction or a plaintext file. The service authenticates the calling UID.
interface IBifrostRootRuntime {
    Bundle exchange(in Bundle request, in ParcelFileDescriptor payload);
}
