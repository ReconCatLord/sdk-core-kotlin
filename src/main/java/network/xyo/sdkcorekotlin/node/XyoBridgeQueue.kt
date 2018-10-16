package network.xyo.sdkcorekotlin.node

/**
 * A class to manage outgoing origin blocks for bridges and sentinels.
 */
open class XyoBridgeQueue {
    private val listeners = HashMap<String, XyoBridgeQueueListener>()
    private val blocksToBridge = ArrayList<XyoBridgeQueueItem>()

    /**
     * The maximum number of blocks to send at a given time.
     */
    var sendLimit = 8

    /**
     * The point at witch blocks should be removed from the queue.
     */
    var removeWeight = 10

    /**
     * Adds a listener to the queue.
     *
     * @param key The key of the listener to add.
     * @param listener The listener to add.
     */
    fun addListener (key : String, listener : XyoBridgeQueueListener) {
        listeners[key] = listener
    }

    /**
     * Removes a listener from the queue.
     *
     * @param key The key of the listener to remove.
     */
    fun removeListiner (key : String) {
        listeners.remove(key)
    }

    /**
     * Adds an origin block into the bridge queue.
     *
     * @param blockHash The block to add.
     */
    fun addBlock (blockHash : ByteArray) {
        blocksToBridge.add(XyoBridgeQueueItem(blockHash, 0))
        sortQueue()
    }

    /**
     * Adds an origin block into the bridge queue with a weight.
     *
     * @param blockHash The block to add.
     * @param weight The weight to add the block to the queue with.
     */
    fun addBlock (blockHash : ByteArray, weight : Int) {
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
        val toRemove = ArrayList<XyoBridgeQueueItem>()

        for (block in blocksToBridge) {
            if (block.weight >= mask) {
                toRemove.add(block)
            }
        }

        for (block in toRemove) {
            removeBlock(block)
        }
    }

    /**
     * Gets the current list of origin blocks to send.
     *
     * @return An array of blocks to send to the bridge.
     */
    fun getBlocksToBridge () : Array<ByteArray> {
        sortQueue ()
        val toRemove = ArrayList<XyoBridgeQueueItem>()
        val toBridge = ArrayList<ByteArray>()

        for (i in 0 until Math.min(sendLimit, blocksToBridge.size)) {
            val block = blocksToBridge[i]
            toBridge.add(block.boundWitnessHash)
            block.weight++

            if (block.weight >= removeWeight) {
                toRemove.add(block)
            }
        }

        for (block in toRemove) {
            removeBlock(block)
        }

        return toBridge.toTypedArray()
    }

    private fun sortQueue () {
        blocksToBridge.sort()
    }

    private fun removeBlock (block: XyoBridgeQueueItem) {
        blocksToBridge.remove(block)

        for ((_, listener) in listeners) {
            listener.onRemove(block.boundWitnessHash)
        }
    }

    companion object {

        /**
         * A Listener for a XyoBridgeQueue
         */
        interface XyoBridgeQueueListener {
            /**
             * This function gets called evey time a block gets removed from the queue.
             */
            fun onRemove(boundWitnessHash: ByteArray)
        }

        private class XyoBridgeQueueItem (val boundWitnessHash: ByteArray, var weight: Int) : Comparable<XyoBridgeQueueItem> {
            override fun compareTo(other: XyoBridgeQueueItem): Int {
                return weight.compareTo(other.weight)
            }
        }
    }
}