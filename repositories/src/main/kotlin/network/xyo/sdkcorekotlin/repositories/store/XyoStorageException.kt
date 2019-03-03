package network.xyo.sdkcorekotlin.repositories.store

import network.xyo.sdkcorekotlin.XyoException

/**
 * An exception for the StorageProviderInterface. Can throw during writing, reading, deleting, and other repositories
 * related operations.
 *
 * @property message The message describing the repositories exception/
 */
class XyoStorageException (override val message: String?) : XyoException()