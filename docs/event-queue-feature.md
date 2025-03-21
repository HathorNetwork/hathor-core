# Feature: event queue

## Introduction

Before the Event Queue feature, applications that wanted to interact with the full node had to write their own sync algorithm from scratch to handle all cases, such as reorgs. This algorithm could become very complex and take several days of development, as it had to know how to query all affected vertices and update them on the application's database.
Also, there was no order guarantee when listening to WebSocket messages, and if the connection dropped, messages might have been lost and a resync was necessary.

With the Event Queue feature, the integration is simpler and more reliable. Events are emitted in a way the application doesn't need to have internal knowledge on how to handle cases such as reorgs, since explicit changes are emitted and the application can react accordingly. Also, the event order is guaranteed, and if the connection is dropped, the application can request a new stream of events from the last event it processed successfully.

**ATTENTION**: The Event Queue feature is currently in beta and must not be used in production environments.

## What is it?

When the Event Queue feature is enabled, the full node will generate specific events reflecting what's happening during its sync. Those events are persisted by the full node in its database, and are available for retrieval through both an HTTP API, and a WebSocket API, for a continue stream of events. Events are generated, for example, when a new vertex is received from the network or when a reorg starts and finishes.

## Enabling the Event Queue

To enable the Event Queue feature, you must add this CLI option when running the full node: `--enable-event-queue`.

For example:

```bash
poetry run hathor-cli run_node --temp-data --status 8080 --testnet --enable-event-queue
```

### First run

If this is the first time your full node is running with the event queue enabled, there are 2 possibilities:

1. You're performing a sync from scratch or you're using a temporary database (like in the example above), that is, you don't have an existing database, or
2. You're running from an existing database.

For case 1, the full node will start normally, events will be generated in real time while vertices are synced and they'll be sent to the WebSocket connection accordingly, as explained below.

For case 2, an extra loading step will be performed during full node initialization, generating events for all existing vertices in your database. This step is slower than normal full node initialization and can take several minutes. Note that this will only be necessary once — after initialization, the events generated for your database are persisted and will be used in subsequent runs.

### Subsequent runs when using RocksDB

After running the full node with the Event Queue enabled, if you restart your full node (that is, stop it and then run it again), there are 2 possibilities:

1. You run the full node with the `--enable-event-queue` CLI option, that is, you keep the Event Queue enabled, or
2. You run the full node without the CLI option, that is, you don't enable it, but you **have to clear the event data in the database**.

For case 1, the full node will start normally, and continue to generate new events for synced vertices from where it stopped in the previous run.

For case 2, before starting the full node, you have to run the following command:

```bash
poetry run hathor-cli reset-event-queue --data /path/to/my_database
```

Then, all Event Queue related data will be removed from the database. You can start the full node and it will initialize normally, without any generation and emission of events. Note that no vertex data will be lost from your database, only Event Queue related data.

If you were to initialize the full node without running the reset command first, you would get an initialization error. If that was allowed, the full node would sync vertices without generating events for them, and that would result in an event gap in the database. Therefore, it is not allowed.

If after disabling it you then enable it again in another restart, the full node will behave like in the first run described above.

**ATTENTION**: If you reset the Event Queue and then enable it again, a client application would have to know that the events it has processed are now invalid, and must reset them too, reprocessing all events from the beginning as they're generated again by the full node. In the future, an ID will be provided for each Event Queue run, and requesting events from a different run will result in an error.

## Interacting with the Event Queue

For an application to interact with the Event Queue, both an HTTP API and a WebSocket API are provided. The WebSocket is preferred.

## HTTP API

### GET Endpoint

#### Description

The `GET` endpoint returns a list of events starting from a specific event ID.

#### Endpoint

`GET /event?last_ack_event_id=[last_ack_event_id]&size=[size]`

#### Query params

- `last_ack_event_id`: the last event ID the application has acknowledged. That is, the returned event list will contain events starting from `event_id = last_ack_event_id + 1`. Can be `null` if the application hasn't acknowledged any events.
- `size`: the batch size of returned events. Cannot be greater than `1000`. Default is `100`.

#### Response schema

The response contains the requested event batch and the `latest_event_id`, that can be used by clients to know how far they're from real time events.

| Attribute         | Type              | Description                                          |
|-------------------|-------------------|------------------------------------------------------|
| `latest_event_id` | `Optional[int]`   | The last event ID the full node has in its database. |
| `events`          | `List[BaseEvent]` | The batch of events.                                 |

The schema for `BaseEvent` can be found in the Schemas section.

#### Errors

- If `last_ack_event_id` is an event that does not exist (example: last `event_id` on database is 1000, but client pass 2000 as `last_received`), the API will return `404 - Not Found`.
- If client pass a `size` <= 1 or > 1000, the API will return `400 - Bad Request`, informing that size is out of range.

#### Example

`GET http://localhost:8080/v1a/event?size=1`

```json
{
    "events": [
        {
            "peer_id": "ca084565aa4ac6f84c452cb0085c1bc03e64317b64e0761f119b389c34fcfede",
            "id": 0,
            "timestamp": 1686186579.306944,
            "type": "LOAD_STARTED",
            "data": {},
            "group_id": null
        }
    ],
    "latest_event_id": 9038
}
```

## WebSocket API

To use the WebSocket API, connect to `/event_ws`, for example:

```bash
wscat -c ws://localhost:8080/v1a/event_ws
```

The event stream *won't* start right away, you have to start it. More on that below. After the stream is started, the client will receive event messages. Messages will have a sequential `event_id` starting from 0, and it is the client's responsibility to store the last event received and processed. In case a connection dies, the new connection will not know where it stopped, so the client must pass that information to the server. Below are all possible message types, both from client to server, and from server to client.

### Start Stream Request

Tell WebSocket to start streaming events from a certain `event_id`.

#### Direction

`Client -> Server`

#### Message Body

| Field               | Type            | Description                                                                                                                                                  |
|---------------------|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `type`              | `str`           | The message type: `START_STREAM`.                                                                                                                            |
| `last_ack_event_id` | `Optional[int]` | The last `event_id` the client has received, so the stream starts from the event after that one. `None` if the client wants to receive from the first event. |
| `window_size`       | `int`           | The number of events the client is able to process before acknowledging that it received some event.                                                         |

### Stop Stream Request

Tell WebSocket to stop streaming events.

#### Direction

`Client -> Server`

#### Message Body

| Field  | Type  | Description                      |
|--------|-------|----------------------------------|
| `type` | `str` | The message type: `STOP_STREAM`. |

### ACK Request

Tell WebSocket that the client acknowledges that it receive a certain `event_id`. Also used to control the flow of events via the `window_size` field.

#### Direction

`Client -> Server`

#### Message Body

| Field          | Type  | Description                                                                                       |
|----------------|-------|---------------------------------------------------------------------------------------------------|
| `type`         | `str` | The message type: `ACK`.                                                                          |
| `ack_event_id` | `int` | The last `event_id` the client has received, so the available window is calculated from that one. |
| `window_size`  | `int` | The number of events the client is able to process before acknowledging another event.            |

### Event Response

Event data the Server sends to the Client.

#### Direction

`Server -> Client`

#### Message Body

| Field             | Type        | Description                                                                                                           |
|-------------------|-------------|-----------------------------------------------------------------------------------------------------------------------|
| `type`            | `str`       | The message type: `EVENT`.                                                                                            |
| `event`           | `BaseEvent` | The event.                                                                                                            |
| `latest_event_id` | `int`       | The ID of the last event the server has processed. Useful for the Client to know how far it is from real time events. |

### Invalid Request Response

Error message the Server sends to the Client when the Client has performed an invalid request.

#### Direction

`Server -> Client`

#### Message Body

| Field             | Type                 | Description                                                                                                     |
|-------------------|----------------------|-----------------------------------------------------------------------------------------------------------------|
| `type`            | `InvalidRequestType` | The message type. Options described below.                                                                      |
| `invalid_request` | `Optional[str]`      | The request that was invalid, or `None` if there was no request (read the `EVENT_WS_NOT_RUNNING` option below). |
| `error_message`   | `Optional[str]`      | A human-readable description of why the request was invalid.                                                    |

Here are the possible values of the `InvalidRequestType` enum type:

- `EVENT_WS_NOT_RUNNING`: Sent when the Client connection opens to the WebSocket Server, but the server has not yet been started. The `invalid_request` field on the response is empty.
- `STREAM_IS_ACTIVE`: Sent when the Client tries to start a stream that is already started.
- `STREAM_IS_INACTIVE`: Sent when the Client tries to either send an ACK or stop message to a stream that is not running.
- `VALIDATION_ERROR`: Sent when the Client tries to send a request with a malformed body.
- `ACK_TOO_SMALL`: Sent when the Client tries to send an ACK `event_id` that is smaller than the last ACK `event_id` it has sent.
- `ACK_TOO_LARGE`: Sent when the Client tries to send an ACK `event_id` that is larger than the last event the Server has sent.


## Event Simulator

During development, a client can test its integration with the Event Queue feature by simulating different scenarios. To do that, the `events_simulator` CLI tool is provided. It emits fake events via WebSocket that represent a real use case.

The following arguments are accepted:

- `--scenario`: the scenario to simulate. One of `ONLY_LOAD`, `SINGLE_CHAIN_ONE_BLOCK`, `SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS`, and `REORG`.
- `--port`: the port to expose the WebSocket on. Default is `8080`.

Example:

```bash
poetry run hathor-cli events_simulator --scenario REORG
```

## Schemas

Below are the schema definitions for types used above.

### BaseEvent

| Attribute   | Type                                  | Description                                                                                                                                                                                                                                                                                               |
|-------------|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `peer_id`   | `str`                                 | Full node ID. Different full nodes can have different sequences of events.                                                                                                                                                                                                                                |
| `id`        | `int`                                 | Unique and sequential event ID.                                                                                                                                                                                                                                                                           |
| `timestamp` | `float`                               | Timestamp in which the event was generated, in unix seconds. This is only informative, as events aren't guaranteed to have sequential timestamps. For example, if the system clock changes between two events, it's possible that timestamps won't be ordered. Always use the `id` for reliable ordering. |
| `type`      | `EventType`                           | The event type.                                                                                                                                                                                                                                                                                           |
| `data`      | `EmptyData`, `TxData`, or `ReorgData` | Data for this event. Its schema depends on `type`.                                                                                                                                                                                                                                                        |
| `group_id`  | `Optional[int]`                       | Used to link events, for example, many events will have the same `group_id` when they belong to the same reorg process.                                                                                                                                                                                   |


### EventType

One of:

| Value                     | Description                                                                                                                                                                                                                                                    | Related data type |
|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|
| `LOAD_STARTED`            | Will be triggered when the full node is initializing and starts reading from the local database.                                                                                                                                                               | `EmptyData`       |
| `LOAD_FINISHED`           | Will be triggered when the full node is ready to establish new connections, sync, and exchange transactions.                                                                                                                                                   | `EmptyData`       |
| `NEW_VERTEX_ACCEPTED`     | Will be triggered when a vertex is synced, and the consensus algorithm immediately identifies it as an accepted vertex.                                                                                                                                        | `TxData`          |
| `REORG_STARTED`           | Will be triggered when a reorg process starts, that is, the best chain changes. Starts a new event group.                                                                                                                                                      | `ReorgData`       |
| `REORG_FINISHED`          | Will be triggered when a reorg process finishes, that is, a new best chain was found. Closes the event group opened by the previous `REORG_STARTED` event.                                                                                                     | `EmptyData`       |
| `VERTEX_METADATA_CHANGED` | Will be triggered when the metadata for a vertex changes. This will happen both for new vertices and for vertices that are affected during a reorg. In the latter case, these events will belong to the same event group as the reorg start and finish events. | `TxData`          |


### EmptyData

This type contains no attributes.

### TxData

| Attribute      | Type             | Description                                                               |
|----------------|------------------|---------------------------------------------------------------------------|
| `hash`         | `str`            | The hash of this vertex.                                                  |
| `nonce`        | `Optional[int]`  | The nonce of this vertex.                                                 |
| `timestamp`    | `int`            | The timestamp of this vertex.                                             |
| `version`      | `int`            | The version of this vertex.                                               |
| `weight`       | `float`          | The weight of this vertex.                                                |
| `inputs`       | `List[TxInput]`  | The inputs of this vertex.                                                |
| `outputs`      | `List[TxOutput]` | The outputs of this vertex.                                               |
| `parents`      | `List[str]`      | The hashes of this vertex's parents.                                      |
| `tokens`       | `List[str]`      | The tokens of this vertex.                                                |
| `token_name`   | `Optional[str]`  | The token name of this vertex, if it is a `TokenCreationTransaction`.     |
| `token_symbol` | `Optional[str]`  | The token symbol of this vertex, if it is a `TokenCreationTransaction`.   |
| `metadata`     | `TxMetadata`     | The metadata of this vertex.                                              |
| `aux_pow`      | `Optional[str]`  | The auxiliary Proof of Work of this vertex, if it is a `MergeMinedBlock`. |

### ReorgData

| Attribute             | Type  | Description                                                              |
|-----------------------|-------|--------------------------------------------------------------------------|
| `reorg_size`          | `int` | The amount of blocks affected by this reorg.                             |
| `previous_best_block` | `str` | The hash of the best block before this reorg happened.                   |
| `new_best_block`      | `str` | The hash of the best block after this reorg.                             |
| `common_block`        | `str` | The hash of the last common block between the two differing blockchains. |

### TxMetadata

| Attribute            | Type                |
|----------------------|---------------------|
| `hash`               | `str`               |
| `spent_outputs`      | `List[SpentOutput]` |
| `conflict_with`      | `List[str]`         |
| `voided_by`          | `List[str]`         |
| `received_by`        | `List[int]`         |
| `children`           | `List[str]`         |
| `twins`              | `List[str]`         |
| `accumulated_weight` | `float`             |
| `score`              | `float`             |
| `first_block`        | `Optional[str]`     |
| `height`             | `int`               |
| `validation`         | `str`               |

### TxInput

| Attribute | Type  |
|-----------|-------|
| `tx_id`   | `str` |
| `index`   | `int` |
| `data`    | `str` |

### TxOutput

| Attribute    | Type  |
|--------------|-------|
| `value`      | `int` |
| `script`     | `str` |
| `token_data` | `int` |

### SpentOutput

| Attribute | Type        |
|-----------|-------------|
| `index`   | `int`       |
| `tx_ids`  | `List[str]` |

## Related links

- [High-level design](https://github.com/HathorNetwork/rfcs/blob/master/projects/reliable-integration/0001-high-level-design.md)
- [Low-level design](https://github.com/HathorNetwork/rfcs/blob/master/projects/reliable-integration/0002-low-level-design.md)
