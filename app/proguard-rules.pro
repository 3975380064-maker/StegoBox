# ---------------- StegoBox release rules ----------------
# We use only Bouncy Castle's *lightweight* API (no JCE provider, no ASN.1).
# Keep just those packages so R8 can drop the huge asn1/jcajce/pkix/tls/pqc parts.

-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

-keep class org.bouncycastle.crypto.CipherParameters { *; }
-keep class org.bouncycastle.crypto.BlockCipher { *; }
-keep class org.bouncycastle.crypto.StreamCipher { *; }
-keep class org.bouncycastle.crypto.BufferedBlockCipher { *; }

-keep class org.bouncycastle.crypto.engines.** { *; }
-keep class org.bouncycastle.crypto.modes.** { *; }
-keep class org.bouncycastle.crypto.digests.** { *; }
-keep class org.bouncycastle.crypto.generators.** { *; }
-keep class org.bouncycastle.crypto.params.** { *; }
-keep class org.bouncycastle.crypto.paddings.** { *; }
-keep class org.bouncycastle.crypto.macs.** { *; }
-keep class org.bouncycastle.crypto.util.** { *; }
-keep class org.bouncycastle.util.** { *; }

# Keep our own crypto/container entry points explicit (defensive)
-keep class com.stegolab.stegobox.crypto.** { *; }
-keep class com.stegolab.stegobox.container.** { *; }