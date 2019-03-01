package network.xyo.sdkcorekotlin.crypto.signing.ecdsa

import kotlinx.coroutines.runBlocking
import network.xyo.sdkcorekotlin.XyoTestBase
import network.xyo.sdkcorekotlin.crypto.signing.ecdsa.XyoEcPrivateKey
import network.xyo.sdkcorekotlin.crypto.signing.ecdsa.secp256k.XyoEcSecp256K1
import network.xyo.sdkcorekotlin.crypto.signing.ecdsa.secp256k.XyoSha256WithSecp256K
import network.xyo.sdkcorekotlin.schemas.XyoSchemas.EC_PRIVATE_KEY
import network.xyo.sdkobjectmodelkotlin.buffer.XyoBuff
import org.bouncycastle.jce.spec.ECParameterSpec
import org.junit.Assert
import org.junit.Test
import java.math.BigInteger

class XyoSecp256k1CryptoStandardTest : XyoTestBase() {

    @Test
    fun testSecp256k1CryptoStandard () {
        runBlocking {
            val dataToSign = "00".hexStringToByteArray()
            val assertedPublic = "DC26168A6630A280E7152FD2749F60BC59EDAC0544276B7F55C91FC57141E4E510D55149DEB84941BC68EC863A9288A65EB485B631F08BD9DC0AA65F5F5E2D12".hexStringToByteArray()
            val assertedPrivate = "00DECCC9FA76EF2D0D90D5C5C9807C25E5429C5202D35A8F5D5C9A3CD7DE0B26EF".hexStringToByteArray()
            val ec = XyoSha256WithSecp256K(XyoEcPrivateKey.getInstance(XyoBuff.newInstance(EC_PRIVATE_KEY, assertedPrivate).bytesCopy, XyoEcSecp256K1.ecSpec))
            val sig = ec.signData(dataToSign).await()

            println(ec.publicKey.valueCopy.toHexString())
            Assert.assertArrayEquals(assertedPublic, ec.publicKey.valueCopy)
            Assert.assertArrayEquals(assertedPrivate, ec.privateKey.valueCopy)
            Assert.assertTrue(XyoSha256WithSecp256K.verifySign(sig, dataToSign, ec.publicKey).await())
        }
    }

    @Test
    fun testSecp256k1CryptoStandard2 () {
        runBlocking {
            val dataToSign = "010203".hexStringToByteArray()
            val assertedPrivate = "0303030303030303030303030303030303030303030303030303030303030303".hexStringToByteArray()
            val ec = XyoSha256WithSecp256K(XyoEcPrivateKey.getInstance(XyoBuff.newInstance(EC_PRIVATE_KEY, assertedPrivate).bytesCopy, XyoEcSecp256K1.ecSpec))
            val sig = ec.signData(dataToSign).await()

            println((ec.keyPair.public as XyoUncompressedEcPublicKey).x.toByteArray().toHexString())
            println((ec.keyPair.public as XyoUncompressedEcPublicKey).y.toByteArray().toHexString())

            Assert.assertArrayEquals(assertedPrivate, ec.privateKey.valueCopy)
            Assert.assertTrue(XyoSha256WithSecp256K.verifySign(sig, dataToSign, ec.publicKey).await())
        }
    }


    @Test
    fun testSecp256k1CryptoStandard3 () {
        runBlocking {


            val r = BigInteger("01E0DB9602AD798C3B4BD11CB9D1005DAD5D219C2F8234B97A543175AF809450", 16)
            val s = BigInteger("00C48D625546CDEA4B040CF34E38EA8845BEBE9E001B58C7EF089605741BA5ED06", 16)
            val sig = XyoEcdsaSignature(r, s)
            val pub = object : XyoUncompressedEcPublicKey() {
                override val ecSpec: ECParameterSpec
                    get() = XyoEcSecp256K1.ecSpec
                override val allowedOffset: Int
                    get() = 0

                override val x: BigInteger
                    get() = BigInteger("00B7F8B44D9234B7B1CA23E9B98CDDA51BEB8384975D469DD5CF683AE505E2B263", 16)

                override val y: BigInteger
                    get() = BigInteger("2BE9CCF189FDA7B36E6CBC3612569AA3784C25264A36C1FF9DD5DC958A212F84", 16)
            }

            println(XyoSha256WithSecp256K.verifySign(sig, byteArrayOf(0x00, 0x00, 0x00, 0x01, 0x01), pub).await())


        }
    }
}
