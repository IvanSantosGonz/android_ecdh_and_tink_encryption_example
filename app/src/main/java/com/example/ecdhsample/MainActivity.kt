package com.example.ecdhsample

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.ecdhsample.ui.theme.ECDHSampleTheme
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.subtle.AesGcmJce
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ECDHSampleTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Greeting("Android")
                }
            }
        }

        val aliceKpg: KeyPairGenerator = KeyPairGenerator.getInstance("EC")
        aliceKpg.initialize(256) // Key size in bits

        val aliceKeyPair: KeyPair = aliceKpg.generateKeyPair()

        // Generate key pair for Bob
        val bobKpg: KeyPairGenerator = KeyPairGenerator.getInstance("EC")
        bobKpg.initialize(256) // Key size in bits

        val bobKeyPair: KeyPair = bobKpg.generateKeyPair()

        // Alice's private key and Bob's public key
        val alicePrivateKey: PrivateKey = aliceKeyPair.private
        val bobPublicKey: PublicKey = bobKeyPair.public

        // Alice performs the key agreement

        // Alice performs the key agreement
        val aliceKeyAgreement: KeyAgreement = KeyAgreement.getInstance("ECDH")
        aliceKeyAgreement.init(alicePrivateKey)
        aliceKeyAgreement.doPhase(bobPublicKey, true)

        // Generate shared secret
        val sharedSecretAlice: ByteArray = aliceKeyAgreement.generateSecret()

        // Bob performs the key agreement
        val bobPrivateKey: PrivateKey = bobKeyPair.private
        val alicePublicKey: PublicKey = aliceKeyPair.public

        val bobKeyAgreement: KeyAgreement = KeyAgreement.getInstance("ECDH")
        bobKeyAgreement.init(bobPrivateKey)
        bobKeyAgreement.doPhase(alicePublicKey, true)

        // Generate shared secret
        val sharedSecretBob: ByteArray = bobKeyAgreement.generateSecret()

        // Compare the shared secrets
        Log.d("Alice's shared secret: ", byteArrayToHexString(sharedSecretAlice)!!)
        Log.d("Bob's shared secret: ", byteArrayToHexString(sharedSecretBob)!!)

        AeadConfig.register()

        // 1. Divide by two the shared secret to have a 128 bit key
        val keyset128 = sharedSecretBob.take(16)
        val aead = AesGcmJce(keyset128.toTypedArray().toByteArray())

        // 3. Use the primitive to encrypt a plaintext
        val plainText = "This is a random message"

        val ciphertext = aead.encrypt(plainText.toByteArray(), null)
        Log.d("encrypted message = ", String(ciphertext))

        // ... or to decrypt a ciphertext.
        val decrypted = aead.decrypt(ciphertext, null)
        Log.d("decrypted message = ", String(decrypted))

    }

    private fun byteArrayToHexString(array: ByteArray): String? {
        val sb = StringBuilder()
        for (b in array) {
            sb.append(String.format("%02X", b))
        }
        return sb.toString()
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    ECDHSampleTheme {
        Greeting("Android")
    }
}