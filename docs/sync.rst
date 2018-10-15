
Node Sync
=========

Node sync is an important part of the p2p network. When two peers connect, they have to sync their DAGs.

The syncing algorithm is based on the timestamp of the transactions. As both the timestamp of parents and the timestamp of spent outputs must be less than the transaction's timestamp, sorting the transactions by timestamp is a topological sort of the DAG, i.e., when we visit a transaction, all its parents and spent outputs has already been visited.

Another three important properties of the timestamp for syncing are: (i) two nodes are synced at a given timestamp if, and only if, their tips are the same; (ii) if two nodes are synced at timestamp `T`, then they are synced for any timestamp before `T`; and (iii) if two nodes are not synced at timestamp `T`, then they are not synced for any timestamp after `T`.

Using these properties, we may use both exponential and binary search to find `T` such that two nodes are synced at `T`, but they are not synced at `T+1`. Thus, we sync the tips, and increase `T` to `T+1`.

The exponential and binary search uses a *GET-TIPS* message, which returns a hash of the tips at `T`. If the hash is the same, they have the same tips. If it is not, they need to sync.

The searching window is from node's first timestamp `T_{min}` and node's latest timestamp `T_{max}`. The exponential search start at `T=T_{max}` and goes down up to `T_{min}`. It follows the following path: `t_0=T_{max}`, `t_1=T_{max}-1`, `t_2=T_{max}-2`, `t_3=T_{max}-4`, `t_4=T_{max}-8`, and so on. When it finds `t_k` in which they are synced, a binary search is performanced in the interval between `t_k` and `t_{k-1}`.

The binary search between `t_k` and `t_{k-1}` is necessary because we know that the peers are synced at `t_{k-1}` and not synced at `t_k`, but we need to find `T` such that the peers are synced at `T` and not synced at `T+1`. For example, when `T_{max}=100` and `k=4`, then `t_4 = 100-8 = 92`, `t_3 = 100-4 = 96`, and we still need to find for which `T` between 92 and 96 we are synced at `T` and not synced at `T+1`.

To sync at `T`, the nodes send a *GET-TIPS* message with the hashes of the tips included. Then, they check which hashes are unknown and download them.

Every one second, the nodes check whether they are still synced using the node's latest timestamp. If they are not synced, they start to sync again.


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


Theorem 5: Let A and B be DAGs. If A(d) != B(d), then A(i) != B(i) for i > d.

Proof: Suppose A(i) = B(i). Then, as A(d) is a subDAG of A(i) and B(d) is a subDAG of B(i), we would have A(d) = B(d), which is a contradiction.


Thanks to Theorem 4 and Theorem 5, we can use binary search to find $d$ such as A(d) = B(d).

