package com.oguzhanstech.hybridvpn.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small secrets at rest (VPN profiles with private keys, passwords), encrypted with an AES-GCM key
 * that lives in the Android Keystore and never leaves it. Files hold IV ‖ ciphertext. App storage
 * is already private to the app and excluded from backups; this also keeps the secrets unreadable
 * in a copy of the app's files.
 */
class SecretStore(private val dir: File) {

    fun write(name: String, plaintext: ByteArray) {
        dir.mkdirs()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(cipher.iv + cipher.doFinal(plaintext))
        if (!tmp.renameTo(File(dir, name))) {
            tmp.delete()
            error("could not store secret $name")
        }
    }

    /** The secret, or null if it doesn't exist or can't be decrypted (e.g. the key was removed). */
    fun read(name: String): ByteArray? {
        val file = File(dir, name)
        if (!file.exists()) return null
        return try {
            val data = file.readBytes()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data, 0, IV_BYTES))
            cipher.doFinal(data, IV_BYTES, data.size - IV_BYTES)
        } catch (_: Exception) {
            null
        }
    }

    fun delete(name: String) {
        File(dir, name).delete()
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "hybridvpn-secrets"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
    }
}
