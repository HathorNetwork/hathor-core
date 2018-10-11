
Node Sync
=========

Node sync is an important part of the p2p network. When two peers connect, they have to sync their DAGs.


Definitions
-----------

Definition 1
^^^^^^^^^^^^
In our DAGs, both transactions and blocks are vertices. If an edge goes from :math:`X_2` to :math:`X_1`, then we say that :math:`X_2` is validating :math:`X_1`, or, :math:`X_1 \leftarrow X_2`. We say :math:`X_1` is a parent of :math:`X_2`, and :math:`X_2` is a (direct) validator of :math:`X_1`.

Definition 2
^^^^^^^^^^^^
Genesis transactions are the starting vertices of the DAGs. They are shared by all DAGs, and they are the only vertices allowed to have no parents. All other vertices must have parents.

Definition 3
^^^^^^^^^^^^
Two DAGs are synced when they are equal, i.e., they have the same vertices and edges.

Definition 4
^^^^^^^^^^^^
The tips of a DAG are the vertices with no inbound edges, i.e., all transactions that don't have any validation.

Definition 5
^^^^^^^^^^^^
We say that two transactions are the same when they have the same hash, which happens when all their attributes are equal, and their subDAGs are equal as well.

Definition 6
^^^^^^^^^^^^
Let A be a DAG and X a vertex of A. We say that height(X) is the maximum distance from X to genesis. We say that A(d) is the subgraph made of all vertices with height less or equal to d.


Theorems
--------

Theorem 1: If TX1 and TX2 are equal, then subDAG starting in TX1 is the equal to the subDAG starting in TX2.


Theorem 2: Let DAG_A and DAG_B be two DAGs, and tips_A and tips_B their tips, respectively. Then, DAG_A and DAG_B are synced if, and only if, tips_A = tips_B.
 
Proof:
(=>) If tips_A != tips_B, there is a tip X that belongs to tips_A and doesn't belong to tips_B (or vice-versa). Thus, X belongs to DAG_A but does not belong to DAG_B. But it is a contradiction, because DAG_A and DAG_B are equal. Hence, tips_A must be equal to tips_B.

(<=) Suppose there is a vertex X that exists in DAG_A but does not exist in DAG_B. Then, there is a path from $T \in tips_A$ such as $T -> ... -> X -> ... -> genesis$. But, this tip $T$ cannot be in tips_B, otherwise, X would belong to at least one subDAG_i of tips_B, and thus $X$ would belong to DAG_B. This is a contradiction because tips_A = tips_B.


Theorem 3: Let A be a DAG, and L a list of all vertices of A. Then, any permutation :math:`[x_1, x_2, \dots, x_n]` of L such that :math:`\text{height}(x_i) \le \text{height}(x_j) \, \forall i < j` is a valid topological sort of A.


Theorem 4: Let A and B be DAGs. If A(d) = B(d), then A(i) = B(i) for i < d.

Proof: i<d implies that A(i) is a subDAG of A(d) and B(i) is a subDAG of B(d), which implies that A(i) = B(i).


Theorem 5: Let A and B be DAGs. If A(d) != B(d), then A(i+1) != B(i+1) for i > d.

Proof: Suppose A(i+1) = B(i+1). Then, as A(d) is a subDAG of A(i+1) and B(d) is a subDAG of B(i+1), we would have A(d) = B(d), which is a contradiction.


Thanks to Theorem 4 and Theorem 5, we can use binary search to find $d$ such as A(d) = B(d).

