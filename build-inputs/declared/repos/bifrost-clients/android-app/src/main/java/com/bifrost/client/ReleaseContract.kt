package com.bifrost.client

internal object ReleaseContract {
    const val CONTRACT_ID = "bifrost.release"
    const val CONTRACT_VERSION = "1.2.0"
    const val TRUST_ROOT_KEY_ID = ReleaseTrustBinding.TRUST_ROOT_KEY_ID
    const val RELEASE_SIGNING_KEY_ID = "bifrost-release-v1"
    val TRUST_ROOT_PEM: String? = ReleaseTrustBinding.TRUST_ROOT_PEM
    const val TRUST_ROOT_PROVISIONED = ReleaseTrustBinding.TRUST_ROOT_PROVISIONED
    val TRUST_ROOT_FINGERPRINT: String? = ReleaseTrustBinding.TRUST_ROOT_FINGERPRINT
}
