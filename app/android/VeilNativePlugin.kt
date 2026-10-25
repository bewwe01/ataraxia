package __PACKAGE__

// Copied into the generated Android project by app/android/harden.py. Called only from Rust
// (app/src-tauri/src/native.rs): the app's capability file grants the webview no permission
// for this plugin, and Tauri rejects every `plugin:` IPC call without one (ADR-0012).

import android.app.Activity
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.view.WindowManager
import android.webkit.WebView
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class SealArgs {
  var secret: String = ""
}

@InvokeArg
class OpenArgs {
  var blob: String = ""
}

@InvokeArg
class FlagArgs {
  var value: Boolean = false
}

@TauriPlugin
class VeilNativePlugin(private val activity: Activity) : Plugin(activity) {
  private companion object {
    const val ALIAS = "veil.biometric.v1"
    const val PREFS = "veil_native"
    const val ALLOW_SCREENSHOTS = "allow_screenshots"
    const val IV_LEN = 12
  }

  private fun prefs() = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  override fun load(webView: WebView) {
    // MainActivity sets FLAG_SECURE before anything is drawn; lift it only if the user chose so.
    if (prefs().getBoolean(ALLOW_SCREENSHOTS, false)) {
      activity.runOnUiThread { activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
  }

  private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

  private fun available(): Boolean =
    BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

  @Command
  fun biometricAvailable(invoke: Invoke) {
    invoke.resolve(JSObject().put("value", available()))
  }

  /** A fresh AES-256-GCM key that only a strong biometric can use, once per use. */
  private fun newKey(): SecretKey {
    keyStore().deleteEntry(ALIAS)
    val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    } else {
      @Suppress("DEPRECATION")
      spec.setUserAuthenticationValidityDurationSeconds(-1)
    }
    val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    gen.init(spec.build())
    return gen.generateKey()
  }

  private fun prompt(invoke: Invoke, cipher: Cipher, title: String, done: (Cipher) -> Unit) {
    activity.runOnUiThread {
      val fa = activity as? FragmentActivity
      if (fa == null) {
        invoke.reject("Biometric unlock is not available", "UNAVAILABLE")
        return@runOnUiThread
      }
      val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setNegativeButtonText("Use PIN or password")
        .setAllowedAuthenticators(BIOMETRIC_STRONG)
        .setConfirmationRequired(false)
        .build()
      val bp = BiometricPrompt(fa, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          val c = result.cryptoObject?.cipher
          if (c == null) {
            invoke.reject("Biometric unlock failed", "FAILED")
            return
          }
          try {
            done(c)
          } catch (e: Exception) {
            invoke.reject("Biometric unlock failed", "FAILED")
          }
        }

        override fun onAuthenticationError(code: Int, msg: CharSequence) {
          invoke.reject("Cancelled", "CANCELLED")
        }
      })
      bp.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
  }

  /** Seals a secret from Rust under a new biometric key. Returns iv || ciphertext. */
  @Command
  fun seal(invoke: Invoke) {
    var secret = ByteArray(0)
    try {
      secret = Base64.decode(invoke.parseArgs(SealArgs::class.java).secret, Base64.NO_WRAP)
      if (!available()) {
        invoke.reject("Biometric unlock is not available", "UNAVAILABLE")
        return
      }
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, newKey())
      prompt(invoke, cipher, "Turn on fingerprint unlock") { c ->
        val ct = c.doFinal(secret)
        Arrays.fill(secret, 0)
        val out = c.iv + ct
        invoke.resolve(JSObject().put("blob", Base64.encodeToString(out, Base64.NO_WRAP)))
      }
    } catch (e: Exception) {
      Arrays.fill(secret, 0)
      invoke.reject("Biometric unlock is not available", "UNAVAILABLE")
    }
  }

  /** Opens a sealed blob behind a biometric prompt and returns the secret to Rust. */
  @Command
  fun open(invoke: Invoke) {
    try {
      val blob = Base64.decode(invoke.parseArgs(OpenArgs::class.java).blob, Base64.NO_WRAP)
      if (blob.size <= IV_LEN) {
        invoke.reject("Biometric unlock failed", "FAILED")
        return
      }
      val key = keyStore().getKey(ALIAS, null) as? SecretKey
      if (key == null) {
        invoke.reject("Biometric key is gone", "KEY_GONE")
        return
      }
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      try {
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 0, IV_LEN))
      } catch (e: KeyPermanentlyInvalidatedException) {
        keyStore().deleteEntry(ALIAS)
        invoke.reject("Biometric key is gone", "KEY_GONE")
        return
      }
      prompt(invoke, cipher, "Unlock Veil") { c ->
        val pt = c.doFinal(blob, IV_LEN, blob.size - IV_LEN)
        val s = Base64.encodeToString(pt, Base64.NO_WRAP)
        Arrays.fill(pt, 0)
        invoke.resolve(JSObject().put("secret", s))
      }
    } catch (e: Exception) {
      invoke.reject("Biometric unlock failed", "FAILED")
    }
  }

  @Command
  fun deleteKey(invoke: Invoke) {
    try {
      keyStore().deleteEntry(ALIAS)
    } catch (e: Exception) {
      // Nothing to delete.
    }
    invoke.resolve()
  }

  @Command
  fun setScreenshotsAllowed(invoke: Invoke) {
    val allow = invoke.parseArgs(FlagArgs::class.java).value
    prefs().edit().putBoolean(ALLOW_SCREENSHOTS, allow).apply()
    activity.runOnUiThread {
      if (allow) {
        activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
      } else {
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
      }
    }
    invoke.resolve()
  }

  @Command
  fun screenshotsAllowed(invoke: Invoke) {
    invoke.resolve(JSObject().put("value", prefs().getBoolean(ALLOW_SCREENSHOTS, false)))
  }

  /** Colours the status and navigation bar area to match the app's theme. */
  @Command
  fun setDarkBars(invoke: Invoke) {
    val dark = invoke.parseArgs(FlagArgs::class.java).value
    activity.runOnUiThread {
      activity.window.decorView.setBackgroundColor(if (dark) 0xFF0B0D22.toInt() else 0xFFEEF0FA.toInt())
      val c = WindowCompat.getInsetsController(activity.window, activity.window.decorView)
      c.isAppearanceLightStatusBars = !dark
      c.isAppearanceLightNavigationBars = !dark
    }
    invoke.resolve()
  }
}
