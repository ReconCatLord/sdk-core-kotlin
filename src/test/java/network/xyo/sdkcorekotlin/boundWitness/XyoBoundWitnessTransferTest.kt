package network.xyo.sdkcorekotlin.boundWitness

import network.xyo.sdkcorekotlin.XyoTestBase
import network.xyo.sdkcorekotlin.data.XyoObject
import network.xyo.sdkcorekotlin.data.XyoPayload
import network.xyo.sdkcorekotlin.data.array.multi.XyoKeySet
import network.xyo.sdkcorekotlin.data.array.multi.XyoMultiTypeArrayInt
import network.xyo.sdkcorekotlin.data.heuristics.number.signed.XyoRssi
import network.xyo.sdkcorekotlin.signing.XyoSignatureSet
import network.xyo.sdkcorekotlin.signing.XyoSigner
import network.xyo.sdkcorekotlin.signing.algorithms.ecc.secp256k.XyoSha1WithSecp256K
import network.xyo.sdkcorekotlin.signing.algorithms.ecc.secp256k.XyoSha256WithSecp256K
import network.xyo.sdkcorekotlin.signing.algorithms.ecc.secp256k.keys.XyoSecp256K1UnCompressedPublicKey
import network.xyo.sdkcorekotlin.signing.algorithms.ecc.secp256k.signatures.XyoSecp256k1Sha256WithEcdsaSignature
import network.xyo.sdkcorekotlin.signing.algorithms.rsa.XyoRsaPublicKey
import network.xyo.sdkcorekotlin.signing.algorithms.rsa.signatures.XyoRsaWithSha256Signature
import org.junit.Test

class XyoBoundWitnessTransferTest : XyoTestBase() {
    private val expectedPayloads = arrayOf<XyoObject>(
            XyoPayload(XyoMultiTypeArrayInt(arrayOf(XyoRssi(-34))), XyoMultiTypeArrayInt(arrayOf(XyoRssi(-34))))
    )

    private val expectedKeys : Array<XyoObject>
        get() {
            XyoSha256WithSecp256K.enable()
            XyoSha1WithSecp256K.enable()
            return arrayOf(
                    XyoKeySet(arrayOf(
                            XyoSigner.getCreator(0x02)!!.newInstance().publicKey,
                            XyoSigner.getCreator(0x02)!!.newInstance().publicKey
                    )),
                    XyoKeySet(arrayOf(
                            XyoSigner.getCreator(0x01)!!.newInstance().publicKey,
                            XyoSigner.getCreator(0x02)!!.newInstance().publicKey
                    ))
            )
        }

    private val expectedSignatures = arrayOf<XyoObject>(
            XyoSignatureSet(arrayOf(
                    XyoSecp256k1Sha256WithEcdsaSignature(byteArrayOf(0x00)),
                    XyoRsaWithSha256Signature(byteArrayOf(0x00))
            )),
            XyoSignatureSet(arrayOf(
                    XyoSecp256k1Sha256WithEcdsaSignature(byteArrayOf(0x00))
            ))
    )

    @Test
    fun testTransferPackingAll () {
        XyoRssi.enable()
        XyoKeySet.enable()
        XyoPayload.enable()
        XyoSignatureSet.enable()
        XyoSecp256k1Sha256WithEcdsaSignature.enable()
        XyoRsaWithSha256Signature.enable()
        XyoSecp256K1UnCompressedPublicKey.enable()
        XyoRsaPublicKey.enable()
        XyoSha256WithSecp256K.enable()
        XyoSha1WithSecp256K.enable()

        val expectedTransfer = XyoBoundWitnessTransfer(expectedKeys, expectedPayloads, expectedSignatures)
        val expectedTransferPacked = expectedTransfer.untyped
        val recreated = XyoBoundWitnessTransfer.createFromPacked(expectedTransferPacked)

        assertXyoObject(expectedTransfer, recreated)
    }
}