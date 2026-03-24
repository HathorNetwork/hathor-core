from hathor.nanocontracts.sorter.random_sorter import NCBlockSorter

nc_hashes_list = [
    b'a'*32,
    b'b'*32,
    b'c'*32,
    b'd'*32,
]

sorter = NCBlockSorter(set(nc_hashes_list))

for i in range(1, len(nc_hashes_list)):
    sorter.add_edge(nc_hashes_list[i], nc_hashes_list[0])

seed = b'x' * 32
print(sorter.generate_random_topological_order(seed))
