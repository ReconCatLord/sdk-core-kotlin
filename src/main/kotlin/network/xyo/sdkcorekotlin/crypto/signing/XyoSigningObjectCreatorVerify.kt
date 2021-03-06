package network.xyo.sdkcorekotlin.crypto.signing

import kotlinx.coroutines.Deferred
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import network.xyo.sdkobjectmodelkotlin.buffer.XyoBuff
import java.security.PublicKey
import java.security.Signature

/**
 * A base class for verifying signaturePacking that comply to the standard Java Signature object.
 */
abstract class XyoSigningObjectCreatorVerify : XyoSigner.XyoSignerProvider() {
    /**
     * The instance of a standard Java Signature object to use toi very the signature.
     */
    abstract val signatureInstance : Signature
}