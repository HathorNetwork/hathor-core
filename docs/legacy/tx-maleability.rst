Transaction Maleability
=======================
The digital signature of the inputs and outputs do not cover the parents and the nonce. On one hand, this is important to let the transactions be recoved in case of a split-brain, but, on the other hand, it makes possible to a malicious node to change the transaction hash, or to generate many conflicts.

For example, a malicious node may receive new transactions, change their parents, solve the proof-of-work again, and propagate this new transaction. The original and the transactions will be in conflict because they are trying to spend the same output. At the same time, their inputs and outpus are exactly the same, and it does not matter which one wins the conflict resolution.

When conflicting transactions have the same inputs and ouputs, they are called twin transactions.

Therefore, users should never user the transaction hash to identify whether a transfer has been finished or not. Users must always use the hash of the signing part, which may not be changed by any node.
