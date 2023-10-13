###
# Utilitary functions to run the demo displayed in the Nano Contract Presentation.
#
# How to use: Open a terminal and run the following commands in order:
#
#    $ source demo.sh
#    $ get_blueprint_info | jq
#    $ start_wallet | jq
#    $ get_address | jq
#    $ get_htr_balance | jq
#    $ TOKEN_A=$(create_token_A | jq -r .hash)
#    $ TOKEN_B=$(create_token_B | jq -r .hash)
#    $ get_token_A_balance | jq
#    $ get_token_B_balance | jq
#    $ NC_ID=$(create_nano_contract | jq -r .hash)
#    $ get_nc_history | jq
#    $ get_nc_state | jq
#    $ execute_nc_swap | jq
#    $ get_nc_history | jq
#    $ get_nc_state | jq
###


FULLNODE_URL=http://localhost:8080

WALLET_URL=http://localhost:8000
WALLET_ID=genesis
SEED_KEY=genesis

BLUEPRINT_ID=494d0ac59a6918b771b122395206fef3f349f84f20dc430188a319d4ead24a3b

# TOKEN_A
# TOKEN_B
# NC_ID

get_blueprint_info() {
	curl --location "${FULLNODE_URL}/v1a/nano_contract/blueprint?blueprint_id=${BLUEPRINT_ID}"
}

get_tx_info() {
	curl --location "${FULLNODE_URL}/v1a/transaction?id=$1"
}

start_wallet() {
	curl -s --location "${WALLET_URL}/start/" \
	--header "Content-Type: application/json" \
	--data '{
				"wallet-id": "'${WALLET_ID}'",
				"seedKey": "'${SEED_KEY}'"
	}'
}

get_htr_balance() {
	curl -s --location "${WALLET_URL}/wallet/balance/" \
	--header "Content-Type: application/json" \
	--header "x-wallet-id: ${WALLET_ID}"
}

get_address() {
	curl -s --location "${WALLET_URL}/wallet/address/" \
	--header "Content-Type: application/json" \
	--header "x-wallet-id: ${WALLET_ID}"
}

get_token_A_balance() {
	curl -s --location "${WALLET_URL}/wallet/balance/?token=${TOKEN_A}" \
	--header "Content-Type: application/json" \
	--header "x-wallet-id: ${WALLET_ID}"
}

get_token_B_balance() {
	curl -s --location "${WALLET_URL}/wallet/balance/?token=${TOKEN_B}" \
	--header "Content-Type: application/json" \
	--header "x-wallet-id: ${WALLET_ID}"
}

create_token_A() {
	curl -s --location "${WALLET_URL}/wallet/create-token" \
	--header "Content-Type: application/json" \
	--header "x-wallet-id: ${WALLET_ID}" \
	--data '{
		"name": "TokenA",
		"symbol": "AAA",
		"amount": 100000
	}'
}

create_token_B() {
	curl -s --location "${WALLET_URL}/wallet/create-token" \
	--header "Content-Type: application/json" \
	--header "x-wallet-id: ${WALLET_ID}" \
	--data '{
		"name": "TokenB",
		"symbol": "BBB",
		"amount": 100000
	}'
}

create_nano_contract() {
	local ADDRESS=`get_address | jq -r .address`

	curl -s --location "${WALLET_URL}/wallet/nano-contracts/create" \
	--header "Content-Type: application/json" \
	--header "x-wallet-id: ${WALLET_ID}" \
	--data '{
		"blueprint": "'${BLUEPRINT_ID}'",
		"address": "'${ADDRESS}'",
		"data": {
			"actions": [
				{
					"type": "deposit",
					"token": "'${TOKEN_A}'",
					"data": {
						"amount": 10000
					}
				},
				{
					"type": "deposit",
					"token": "'${TOKEN_B}'",
					"data": {
						"amount": 20000
					}
				}
			],
			"args": [
				{
					"type": "byte",
					"value": "'${TOKEN_A}'"
				},
				{
					"type": "byte",
					"value": "'${TOKEN_B}'"
				},
				{
					"type": "int",
					"value": 1
				},
				{
					"type": "int",
					"value": 1
				}
			]
		}
	}'
}

get_nc_history() {
	curl -s --location "${WALLET_URL}/wallet/nano-contracts/history?id=${NC_ID}" \
	--header "x-wallet-id: ${WALLET_ID}"
}

get_nc_state() {
	curl -s --location --globoff "${WALLET_URL}/wallet/nano-contracts/state?id=${NC_ID}&fields[]=token_a&fields[]=token_b&fields[]=swaps_counter&balances[]=${TOKEN_A}&balances[]=${TOKEN_B}" \
	--header "x-wallet-id: genesis"
}

execute_nc_swap() {
	local ADDRESS=`get_address | jq -r .address`

	curl -s --location "${WALLET_URL}/wallet/nano-contracts/execute" \
	--header "Content-Type: application/json" \
	--header "x-wallet-id: ${WALLET_ID}" \
	--data '{
		"blueprint": "'${BLUEPRINT_ID}'",
		"method": "swap",
		"address": "'${ADDRESS}'",
		"data": {
			"ncId": "'${NC_ID}'",
			"actions": [
				{
					"type": "deposit",
					"token": "'${TOKEN_A}'",
					"data": {
						"amount": 300
					}
				},
				{
					"type": "withdrawal",
					"token": "'${TOKEN_B}'",
					"data": {
						"amount": 300,
						"address": "'${ADDRESS}'"
					}
				}
			],
			"args": []
		}
	}'
}

