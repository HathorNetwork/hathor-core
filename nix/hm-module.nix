{ config, lib, pkgs, ... }:

let
  cfg = config.services.hathor-node;
  inherit (lib) mkEnableOption mkOption mkIf types mkMerge;

  networkFlag =
    if cfg.network == "testnet" then "--testnet"
    else if cfg.network == "nano-testnet" then "--nano-testnet"
    else if cfg.network == "localnet" then "--localnet"
    else null; # mainnet = no flag

  cmdArgs = lib.concatStringsSep " " (lib.filter (x: x != "") ([
    "run_node"
  ]
  ++ lib.optional (networkFlag != null) networkFlag
  ++ lib.optional (cfg.configYaml != null) "--config-yaml ${cfg.configYaml}"
  ++ [ "--data ${cfg.dataDir}" ]
  ++ lib.optional (cfg.peerFile != null) "--peer ${cfg.peerFile}"
  ++ lib.concatMap (l: [ "--listen" l ]) cfg.listen
  ++ lib.concatMap (b: [ "--bootstrap" b ]) cfg.bootstrap
  ++ lib.concatMap (d: [ "--dns" d ]) cfg.dns
  ++ lib.optional (cfg.statusPort != null) "--status ${toString cfg.statusPort}"
  ++ lib.optional (cfg.stratumPort != null) "--stratum ${toString cfg.stratumPort}"
  ++ lib.optional cfg.prometheus "--prometheus"
  ++ lib.optional (cfg.prometheusPrefix != "") "--prometheus-prefix ${cfg.prometheusPrefix}"
  ++ lib.optional (cfg.sentryDsn != null) "--sentry-dsn ${cfg.sentryDsn}"
  ++ lib.optional cfg.walletIndex "--wallet-index"
  ++ lib.optional cfg.utxoIndex "--utxo-index"
  ++ lib.optional cfg.ncIndexes "--nc-indexes"
  ++ lib.optional cfg.enableEventQueue "--enable-event-queue"
  ++ lib.optional cfg.enableDebugApi "--enable-debug-api"
  ++ lib.optional (cfg.cacheSize != null) "--cache-size ${toString cfg.cacheSize}"
  ++ lib.optional cfg.disableCache "--disable-cache"
  ++ lib.optional (cfg.rocksdbCache != null) "--rocksdb-cache ${toString cfg.rocksdbCache}"
  ++ cfg.extraArgs));

in
{
  options.services.hathor-node = {
    enable = mkEnableOption "Hathor Network full-node";

    package = mkOption {
      type = types.package;
      description = "The hathor-core package to use.";
    };

    network = mkOption {
      type = types.enum [ "mainnet" "testnet" "nano-testnet" "localnet" ];
      default = "mainnet";
      description = "Which Hathor network to connect to.";
    };

    configYaml = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a custom configuration YAML file.";
    };

    dataDir = mkOption {
      type = types.str;
      default = "%h/.local/share/hathor-node";
      description = "Data directory for the node. %h is expanded to the user's home directory by systemd.";
    };

    peerFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the peer ID JSON file. If null and generatePeerId is true, one will be generated.";
    };

    generatePeerId = mkOption {
      type = types.bool;
      default = true;
      description = "Whether to auto-generate a peer ID file on first start.";
    };

    listen = mkOption {
      type = types.listOf types.str;
      default = [ "tcp:40403" ];
      description = "Addresses to listen on for P2P connections.";
    };

    bootstrap = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Bootstrap peer addresses to connect to.";
    };

    dns = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Seed DNS entries.";
    };

    statusPort = mkOption {
      type = types.nullOr types.port;
      default = 8080;
      description = "Port for the HTTP status/API server. Set to null to disable.";
    };

    stratumPort = mkOption {
      type = types.nullOr types.port;
      default = null;
      description = "Port for the Stratum mining server. Set to null to disable.";
    };

    prometheus = mkOption {
      type = types.bool;
      default = false;
      description = "Enable Prometheus metrics export.";
    };

    prometheusPrefix = mkOption {
      type = types.str;
      default = "";
      description = "Prefix added to all Prometheus metric names.";
    };

    sentryDsn = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Sentry DSN for error reporting.";
    };

    walletIndex = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the wallet (address-based) transaction index.";
    };

    utxoIndex = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the UTXO index.";
    };

    ncIndexes = mkOption {
      type = types.bool;
      default = false;
      description = "Enable nano contract indexes.";
    };

    enableEventQueue = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the event queue mechanism.";
    };

    enableDebugApi = mkOption {
      type = types.bool;
      default = false;
      description = "Enable _debug/* API endpoints.";
    };

    cacheSize = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Number of transactions to keep in cache.";
    };

    disableCache = mkOption {
      type = types.bool;
      default = false;
      description = "Disable the transaction storage cache entirely.";
    };

    rocksdbCache = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "RocksDB block-table cache size in bytes.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra command-line arguments passed verbatim to hathor-cli run_node.";
    };
  };

  config = mkIf cfg.enable {
    # Generate peer ID on activation if requested
    home.activation.hathorGeneratePeerId = mkIf (cfg.generatePeerId && cfg.peerFile == null) (
      lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        PEER_DIR="${config.home.homeDirectory}/.local/share/hathor-node"
        PEER_FILE="$PEER_DIR/peer_id.json"
        if [ ! -f "$PEER_FILE" ]; then
          mkdir -p "$PEER_DIR"
          ${cfg.package}/bin/hathor-cli gen_peer_id > "$PEER_FILE"
          chmod 0600 "$PEER_FILE"
        fi
      ''
    );

    systemd.user.services.hathor-node = {
      Unit = {
        Description = "Hathor Network full-node";
        After = [ "network-online.target" ];
        Wants = [ "network-online.target" ];
      };

      Service = {
        Type = "simple";
        ExecStart =
          let
            peerArg =
              if cfg.peerFile != null then ""
              else if cfg.generatePeerId then "--peer %h/.local/share/hathor-node/peer_id.json"
              else "";
            fullArgs = "${cfg.package}/bin/hathor-cli ${cmdArgs}"
              + lib.optionalString (peerArg != "") " ${peerArg}";
          in
          fullArgs;
        Restart = "on-failure";
        RestartSec = 10;

        # Hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ReadWritePaths = [ cfg.dataDir ];
        PrivateTmp = true;
      };

      Install = {
        WantedBy = [ "default.target" ];
      };
    };
  };
}
