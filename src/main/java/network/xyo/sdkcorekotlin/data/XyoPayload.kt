package network.xyo.sdkcorekotlin.data

import network.xyo.sdkcorekotlin.XyoError
import network.xyo.sdkcorekotlin.XyoResult
import network.xyo.sdkcorekotlin.data.array.multi.XyoMultiTypeArrayInt
import java.nio.ByteBuffer

class XyoPayload(val signedPayload : XyoMultiTypeArrayInt,
                 val unsignedPayload : XyoMultiTypeArrayInt) : XyoObject() {

    override val data: XyoResult<ByteArray>
        get() = makeEncoded()

    override val id: XyoResult<ByteArray>
        get() = XyoResult(byteArrayOf(major, minor))

    override val sizeIdentifierSize: XyoResult<Int?>
        get() = XyoResult(4)

    val signedPayloadMapping :  XyoResult<HashMap<Int, XyoObject>>
        get() = getMappingOfElements(signedPayload.array)

    val unsignedPayloadMapping : XyoResult<HashMap<Int, XyoObject>>
        get() = getMappingOfElements(signedPayload.array)

    private fun getMappingOfElements (objects : Array<XyoObject>) : XyoResult<HashMap<Int, XyoObject>> {
        val mapping = HashMap<Int, XyoObject>()
        for (element in objects) {
            mapping[element.id.value?.contentHashCode() ?: return XyoResult(XyoError("No element id!"))] = element
        }
        return XyoResult(mapping)
    }

    private fun makeEncoded () : XyoResult<ByteArray> {
        val merger = XyoByteArraySetter(2)
        val signedPayloadUntyped = signedPayload.untyped
        val unsignedPayloadUntyped = unsignedPayload.untyped

        if (unsignedPayloadUntyped.error == null) {
            if (signedPayloadUntyped.error == null) {
                val signedPayloadUntypedValue = signedPayloadUntyped.value ?: return XyoResult(XyoError("signedPayloadUntypedValue is null!"))
                val unsignedPayloadUntypedValue = unsignedPayloadUntyped.value ?: return XyoResult(XyoError("unsignedPayloadUntypedValue is null!"))

                merger.add(signedPayloadUntypedValue, 0)
                merger.add(unsignedPayloadUntypedValue, 1)
                return XyoResult(merger.merge())
            }
            return XyoResult(XyoError(""))
        }
        return XyoResult(XyoError(""))
    }

    companion object : XyoObjectCreator() {
        override val major: Byte
            get() = 0x02

        override val minor: Byte
            get() = 0x04

        override val sizeOfBytesToGetSize: XyoResult<Int?>
            get() = XyoResult(4)

        override fun readSize(byteArray: ByteArray): XyoResult<Int> {
            return XyoResult(ByteBuffer.wrap(byteArray).int)
        }

        override fun createFromPacked(byteArray: ByteArray): XyoResult<XyoObject> {
            val reader = XyoByteArrayReader(byteArray)
            val signedPayloadSize = ByteBuffer.wrap(reader.read(4, 4)).int
            val unsignedPayloadSize =  ByteBuffer.wrap(reader.read(4 + signedPayloadSize, 4)).int

            val signedPayload = reader.read(4, signedPayloadSize)
            val unsignedPayload = reader.read(4 + signedPayloadSize, unsignedPayloadSize)

            val signedPayloadCreated = XyoMultiTypeArrayInt.createFromPacked(signedPayload)
            val unsignedPayloadCreated = XyoMultiTypeArrayInt.createFromPacked(unsignedPayload)

            return XyoResult(XyoPayload(signedPayloadCreated.value as XyoMultiTypeArrayInt, unsignedPayloadCreated.value as XyoMultiTypeArrayInt))
        }
    }
}