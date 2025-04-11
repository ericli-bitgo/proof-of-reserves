# Proof of Reserves

## Overview

This is a multi-levelled proof of reserves implementation that enables O(log n) time verification of proofs. 
This system is implemented using Gnark v0.12.0.

## Architecture

This can be extended to arbitrary layers to preserve O(log n) verification time.

The explanations assume a 2 layer implementation. 

However, the actual implementation is currently 3 layers, leading to an upper limit of 1 billion accounts. This does not change the guarantees.

### Bottom layer: 

_(Private inputs)_ [hash(user1 + balance1), hash(user2 + balance2), ..., hash(user1023 + balance1023)] => **(Public outputs)** merkle_hash_1, hash(merkle_hash_1 + sum(balance1, ..., balance1023))

Repeat for user1024...user2047 to get merkle_hash_2, etc

### Top layer: 

_(Private inputs)_ [hash(merkle_hash_1 + sum(balance1, ..., balance1023)), hash(merkle_hash_2 + sum(balance1024, ..., balance2047)), ...] => **(Public outputs)** merkle_hash_top, hash(merkle_hash_top + sum(total_liability))

sum(total_liability) is also published

## Verifying Proofs

Clients can verify the proof of liabilities in the following manner (assuming that the proof is 2 layered):

BitGo provides:
1) A merkle path for the bottom layer
2) A merkle path for the top layer
3) A zk-snark proof for the bottom layer
4) A zk-snark proof for the top layer
5) The root hash of the top layer
6) The root hash of the bottom layer
7) The total liability sum of the top layer
8) The hash of (5) and the sum of liabilities of the bottom layer

The user knows their userId and account balance.

The user can verify the proof in the following manner:
- Compute their leaf hash w = hash(userId + balance)
- Using the merkle path (1), verify that their leaf hash w is included 
in the merkle tree of the bottom layer with merkle root equal to (6)
- Using the zk-snark proof (3), verify that x = hash(merkle_hash_n + sum(balanceN, ..., balanceN+1023))
is correctly computed from every balance in the bottom layer
- Using the merkle path (2), verify that x is included
in the merkle tree of the bottom layer with merkle root equal to (5)
- Using the zk-snark proof (4), verify that y = hash(merkle_hash_top + sum(total_liability))
- Using the root hash (5) and the total liability sum (7), verify that hash((5) + (7)) == (8)

#### This verifies the proof because (informally) we know that:

1) Every BitGo user has been included in at least one bottom layer proof (since the arbitrary client was included)
2) Every bottom layer proof containing BitGo users was included in the top layer proof (since the arbitrary client was included, and is part of an arbitrary proof)
3) Additional users will not lower the liability sum in a bottom layer proof, and additional bottom layer proofs will not lower the total liability in the top layer proof (proved by circuit)
4) Every bottom layer proof sums to some (private) _s_ such that hash(p_root, s) == p_hash (proved by circuit)
5) Every bottom layer proof included in the top layer sums to _t_, the total liability, where hash(top_root, t) == t_hash (proved by circuit)

From (1), (2), (4), and (5), we can conclude that every BitGo user's balances is included in _t_. 
From (3), we can conclude that _t_ is at least the sum of all included BitGo users' balances.

Therefore, we can conclude that _t_ is at least the sum of all BitGo user liabilities.
