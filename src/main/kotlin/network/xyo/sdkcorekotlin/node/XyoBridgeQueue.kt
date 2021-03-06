package network.xyo.sdkcorekotlin.node

import network.xyo.sdkcorekotlin.log.XyoLog
import network.xyo.sdkobjectmodelkotlin.buffer.XyoBuff

/**
 * A class to manage outgoing origin blocks for bridges and sentinels.
 */
open class XyoBridgeQueue {
    private var blocksToBridge = ArrayList<XyoBridgeQueueItem>()
    private var removed = ArrayList<XyoBuff>()

    /**
     * The maximum number of blocks to send at a given time.
     */
    var sendLimit = 10

    /**
     * The point at witch blocks should be removed from the queue.
     */
    var removeWeight = 3

    /**
     * Adds an origin block into the bridge queue.
     *
     * @param blockHash The block to add.
     */
    fun addBlock (blockHash : XyoBuff) {
        blocksToBridge.add(XyoBridgeQueueItem(blockHash, 0))
        sortQueue()
    }

    /**
     * Adds an origin block into the bridge queue with a weight.
     *
     * @param blockHash The block to add.
     * @param weight The weight to add the block to the queue with.
     */
    fun addBlock (blockHash : XyoBuff, weight : Int) {
        blocksToBridge.add(XyoBridgeQueueItem(blockHash, weight))
        sortQueue()
    }

    /**
     * Will filter to queue for a given weight/mask. For example purgeQueue(1) will remove all
     * blocks with a weight of 1 or higher.
     *
     * @param mask The weight to remove.
     */
    fun purgeQueue (mask : Int) {
        for (block in blocksToBridge) {
            if (block.weight >= mask) {
                removed.add(block.boundWitnessHash)
            }
        }
    }

    /**
     * Gets the current list of origin blocks to send.
     *
     * @return An array of blocks to send to the bridge.
     */
    fun getBlocksToBridge () : XyoBridgeJob {
        sortQueue()

        val toBridge = ArrayList<XyoBridgeQueueItem>()

        for (i in 0 until Math.min(sendLimit, blocksToBridge.size)) {
            XyoLog.logDebug("Bridging Block", TAG)
            toBridge.add(blocksToBridge[i])
        }

        return XyoBridgeJob(toBridge.toTypedArray())
    }

    private fun sortQueue () {
        blocksToBridge.sort()
    }

    /**
     * Get the blocks that have exceeded the removeWeight and are out of the queue
     */
    fun getToRemove () : Array<XyoBuff> {
        val result = removed.toTypedArray()
        removed.clear()
        return result
    }

    fun setQueue (blocks : Array<XyoBuff>, weights: Array<Int>) {
        blocksToBridge = ArrayList(Array(blocks.size) { i ->
            XyoBridgeQueueItem(blocks[i], weights[i]) }.asList()
        )
    }

    /**
     * Get all block hashes in the origin block queue. This aligns with getAllBlocks()
     *
     * @return An array of origin block hashes
     */
    fun getAllBlocks () : Array<XyoBuff> {
        return Array(blocksToBridge.size) { i -> blocksToBridge[i].boundWitnessHash }
    }

    /**
     * Get all of the wrights in the queue. This aligns with getAllBlocks()
     *
     * @return an array of Ints that are the weights in the queue.
     */
    fun getAllWeights () : Array<Int> {
        return Array(blocksToBridge.size) { i ->
            blocksToBridge[i].weight
        }
    }

    /**
     * This object is returned from the function getBlocksToBridge()
     *
     * @param blocks The blocks to bridge
     */
    open inner class XyoBridgeJob (val blocks: Array<XyoBridgeQueueItem>) {

        /**
         * The function onSucceed() should be called if bridge job succeed
         */
        open fun onSucceed () {
           for (block in blocks) {
               block.weight++

               if (block.weight >= removeWeight) {
                   blocksToBridge.remove(block)
                   removed.add(block.boundWitnessHash)
               }
           }
        }
    }

    companion object {
        class XyoBridgeQueueItem (val boundWitnessHash: XyoBuff, var weight: Int) : Comparable<XyoBridgeQueueItem> {
            override fun compareTo(other: XyoBridgeQueueItem): Int {
                return weight.compareTo(other.weight)
            }

            override fun equals(other: Any?): Boolean {
                return boundWitnessHash.bytesCopy.contentEquals((other as XyoBridgeQueueItem).boundWitnessHash.bytesCopy)
            }

            override fun hashCode(): Int {
                return boundWitnessHash.bytesCopy.contentHashCode()
            }
        }

        const val TAG = "BQU"
    }
}