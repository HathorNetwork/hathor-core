{ lib
, python3
, poetry2nix
, rocksdb
, snappy
, lz4
, bzip2
, zlib
, pkg-config
, graphviz
, makeWrapper
, stdenv
}:

let
  rocksdbNative = rocksdb;

  overrides = poetry2nix.defaultPoetryOverrides.extend (pyfinal: pyprev: {
    rocksdb = pyprev.rocksdb.overridePythonAttrs (old: {
      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
        pkg-config
        pyfinal.cython
        pyfinal.setuptools
      ];
      buildInputs = (old.buildInputs or [ ]) ++ [
        rocksdbNative
        snappy
        lz4
        bzip2
        zlib
      ];
      ROCKSDB_LIB_DIR = "${rocksdbNative}/lib";
      ROCKSDB_INCLUDE_DIR = "${rocksdbNative}/include";
      # python-rocksdb uses setup.py, not cmake
      dontUseCmakeConfigure = true;
    });

    hathorlib = pyprev.hathorlib.overridePythonAttrs (old: {
      src = ../hathorlib;
      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
        pyfinal.poetry-core
      ];
    });

    python-healthchecklib = pyprev.python-healthchecklib.overridePythonAttrs (old: {
      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
        pyfinal.setuptools
      ];
    });

    # Break ipython ↔ ipykernel circular dependency.
    # ipython[kernel] pulls ipykernel which depends on ipython again.
    # Strip ipykernel from ipython's deps since the kernel extra
    # is not needed for the node runtime.
    ipython = pyprev.ipython.overridePythonAttrs (old: rec {
      dependencies = builtins.filter
        (dep: (dep.pname or (builtins.parseDrvName dep.name).name) != "ipykernel")
        (old.dependencies or [ ]);
      propagatedBuildInputs = dependencies;
    });
  });

  # Build the Python environment with all dependencies
  poetryEnv = poetry2nix.mkPoetryEnv {
    projectDir = ./..;
    python = python3;
    preferWheels = true;
    inherit overrides;
    extras = [ "sentry" ];
  };

in
stdenv.mkDerivation {
  pname = "hathor-core";
  version = "0.70.0";

  src = lib.cleanSourceWith {
    src = ./..;
    filter = path: type:
      let baseName = baseNameOf path; in
      !(builtins.elem baseName [
        ".git" ".venv" ".mypy_cache" "__pycache__"
        ".pytest_cache" "hathor_tests" ".claude"
        "result" ".direnv"
      ]);
  };

  nativeBuildInputs = [ makeWrapper ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib/hathor-core $out/bin

    cp -r hathor hathor_cli hathorlib pyproject.toml $out/lib/hathor-core/

    makeWrapper ${poetryEnv}/bin/python $out/bin/hathor-cli \
      --add-flags "-m hathor_cli.main" \
      --prefix PYTHONPATH : "$out/lib/hathor-core" \
      --prefix LD_LIBRARY_PATH : "${lib.makeLibraryPath [ rocksdbNative ]}" \
      --prefix PATH : "${lib.makeBinPath [ graphviz ]}"

    runHook postInstall
  '';

  meta = with lib; {
    description = "Hathor Network full-node";
    homepage = "https://hathor.network/";
    license = licenses.asl20;
    mainProgram = "hathor-cli";
  };
}
