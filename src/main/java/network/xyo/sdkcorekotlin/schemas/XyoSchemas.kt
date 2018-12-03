package network.xyo.sdkcorekotlin.schemas

import network.xyo.sdkobjectmodelkotlin.schema.XyoObjectSchema


object XyoSchemas {
    // todo fix minor
    val ARRAY_TYPED = XyoObjectSchema.createFromHeader(byteArrayOf(         0xB0.toByte(),        0xCC.toByte()))
    val ARRAY_UNTYPED =  XyoObjectSchema.createFromHeader(byteArrayOf(      0xA0.toByte(),        1.toByte()))

    // todo check if untyped
    val BW = XyoObjectSchema.createFromHeader(byteArrayOf(                  0xA0.toByte(),        2.toByte()))
    val INDEX = XyoObjectSchema.createFromHeader(byteArrayOf(               0x80.toByte(),        3.toByte()))
    val NEXT_PUBLIC_KEY = XyoObjectSchema.createFromHeader(byteArrayOf(     0x80.toByte(),        4.toByte()))
    val BRIDGE_BLOCK_SET = XyoObjectSchema.createFromHeader(byteArrayOf(    0xB0.toByte(),        5.toByte()))
    val BRIDGE_HASH_SET =  XyoObjectSchema.createFromHeader(byteArrayOf(    0xB0.toByte(),        6.toByte()))
    val PAYLOAD = XyoObjectSchema.createFromHeader(byteArrayOf(             0xB0.toByte(),        7.toByte()))
    val PREVIOUS_HASH = XyoObjectSchema.createFromHeader(byteArrayOf(       0x80.toByte(),        8.toByte()))
    val EC_SIGNATURE = XyoObjectSchema.createFromHeader(byteArrayOf(        0x80.toByte(),        9.toByte()))
    val RSA_SIGNATURE = XyoObjectSchema.createFromHeader(byteArrayOf(       0x80.toByte(),        10.toByte()))
    val STUB_SIGNATURE = XyoObjectSchema.createFromHeader(byteArrayOf(      0x80.toByte(),        11.toByte()))
    val EC_PUBLIC_KEY = XyoObjectSchema.createFromHeader(byteArrayOf(       0x80.toByte(),        12.toByte()))
    val RSA_PUBLIC_KEY = XyoObjectSchema.createFromHeader(byteArrayOf(      0x80.toByte(),        13.toByte()))
    val STUB_PUBLIC_KEY = XyoObjectSchema.createFromHeader(byteArrayOf(     0x80.toByte(),        14.toByte()))
    val STUB_HASH = XyoObjectSchema.createFromHeader(byteArrayOf(           0x80.toByte(),        15.toByte()))
    val SHA_256 =  XyoObjectSchema.createFromHeader(byteArrayOf(            0x80.toByte(),        16.toByte()))
    val SHA3 = XyoObjectSchema.createFromHeader(byteArrayOf(                0x80.toByte(),        17.toByte()))
    val GPS = XyoObjectSchema.createFromHeader(byteArrayOf(                 0x80.toByte(),        18.toByte()))
    val RSSI = XyoObjectSchema.createFromHeader(byteArrayOf(                0x80.toByte(),        19.toByte()))
    val UNIX_TIME = XyoObjectSchema.createFromHeader(byteArrayOf(           0x80.toByte(),        20.toByte()))

    val EC_PRIVATE_KEY = XyoObjectSchema.createFromHeader(byteArrayOf(      0x80.toByte(),        0xFF.toByte()))
    val RSA_PRIVATE_KEY = XyoObjectSchema.createFromHeader(byteArrayOf(     0x80.toByte(),        0xFF.toByte()))
}