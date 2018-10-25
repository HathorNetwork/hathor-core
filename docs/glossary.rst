Glossary
========
.. glossary::

    DAG
      Direct acyclic graph in which the vertexes are transactions/blocks, and the direct edges are verifications. If vertex A has an edges to vertex B, we say that transaction A verifies transaction B (and indirectly verifies all transactions verified by transaction B).

    Blockchain
      Chain of blocks inside the DAG.

    Transaction
      A transference of founds from inputs to outputs.

    Block
      A special transaction that issues new tokens.

    Confirmed Transaction
      A transaction that has been confirmed by the network and is very unlikely to be voided, i.e., its accumulated weight is above a given threshold.

    Verified Transaction
      A transaction that has been successfully verified by other transactions.

    Voided Transaction
      A voided transference of funds. Usually transactions are voided because they are verifying other voided transactions or because it is a double-spending transaction with lower accumulated weight.

    Valid Transaction
      A transaction is valid when its funds are valid, and it has not been voided. A valid transaction eventually becomes a confirmed transaction.

    Twin Transaction
      Transactions that have exactly the same inputs and ouputs. Their hash are different because they may have different parents, different timestamps, or simply different nounces.
