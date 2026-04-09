Conflict Resolution
===================
Conflict resolution deals with two situations: (i) blocks out of the longest chain, and (ii) two or more transactions trying to spend the same output.

When two or more transactions try to spend the same output, the conflict resolution will choose at most one transaction as the winner, and the remaining transactions will be voided. If there is a tie in the conflict resolution, there will be no winner, and all transactions in conflict will be voided.

When a new block arrives, all blocks out of the longest chain are voided. Moreover, all transactions spending the issued tokens of a voided block will be voided as well.

There are two types of voided marks: (i) conflict-voided transactions, and (ii) ancestor-voided transactions. The former is when a transaction is voided because it is in conflict with another transaction and loses. The latter is when an ancestor is a conflict voided transaction.

After a transaction is marked as a conflict-voided transaction, its sub-DAG of descendents is also marked as ancestor-voided transactions. When new transactions arrive validating any voided transaction, they are automatically marked as ancestor-voided transaction as well, and only the accumulated weight of the conflict-voided transactions are updated.

The winner of any conflict is always the transaction with the highest accumulated weight that is not ancestor-voided.


Split-brain
-----------
A split-brain happens when the p2p network splits in two or more disconnected groups. In this scenario, new transactions and blocks arrive in different parts of the network and will not be propagated to the whole network. Attackers may use a split-brain as an opportunity to double spend their tokens in disconnected parts of the network. The conflicting transactions will only detect the double spending when merging the parts of the split-brain.

The conflict resolution will be exactly the same as described above. The nodes will merge their transactions, and the winners will be the ones with highest accumulated weight. The same will happen when merging the blocks of different parts. In the end, only the longest chain will be valid, and the others will be voided.

After a split-brain has been merged, the ancestor-voided transactions may be recovered. One just have to choose two new parents, solve the proof-of-work, and propagate it again to the network. This new transaction will be in conflict with the voided one, but the inputs and outputs will be same, so, it does not matter which one is the winner.

It is important to detect a split-brain and generate a notification about it.
