package com.bifrost.client

import org.junit.Assert.assertThrows
import org.junit.Test

class BifrostLargePackageJsonTest {
    @Test fun configurationCiphertextCanExceedTheOrdinaryStringBudget() {
        val text = "{\"config_package\":{\"ciphertext\":\"${"A".repeat(128 * 1024)}\"}}"
        StrictJsonValidator(text, "BF-CONFIG-PACKAGE", allowPackageCiphertext = true).validate()
        assertThrows(IllegalStateException::class.java) {
            StrictJsonValidator(text, "BF-JSON").validate()
        }
    }

    @Test fun packagePermissionDoesNotExpandOrdinaryStringsOrDuplicateKeys() {
        for (text in listOf(
            "{\"message\":\"${"A".repeat(16385)}\"}",
            "{\"ciphertext\":\"AA\",\"ciphertext\":\"BB\"}",
            "{\"ciphertext\":\"${"A".repeat(700000)}\"}",
        )) assertThrows(IllegalStateException::class.java) {
            StrictJsonValidator(text, "BF-CONFIG-PACKAGE", allowPackageCiphertext = true).validate()
        }
    }
}
