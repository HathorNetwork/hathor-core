# Nano Tutorials

## Directory overview

This directory contains interactive Jupyter notebook tutorials for learning Hathor nanocontract development. Each tutorial is self-contained with runnable code examples, comprehensive explanations, and hands-on testing.

The tutorials use the Hathor nanocontracts framework to teach you how to build, test, and deploy smart contracts on the Hathor blockchain.

## Table of contents

Tutorials in this directory:

- **[Blueprint.ipynb](Blueprint.ipynb)** - Creating a Hathor blueprint with the HathorDice game example
  - Understand what blueprints are and how they work
  - Learn the `initialize()` method (the contract constructor)
  - Work with deposits and withdrawals using `NCDepositAction` and `NCWithdrawalAction`
  - Declare allowed actions with the `@public` decorator
  - Validate token types and implement token-specific deposits
  - Test nanocontracts using `BlueprintTestCase`
  - Verify contract balances with `storage.get_balance()`
  - Implement game logic with the `place_bet()` method
  - Emit events for dApp integration with `syscall.emit_event()`
  - Apply defensive programming patterns with assertions
  - Understand return values vs. events in public methods

## Prerequisites

Before starting these tutorials, ensure you have:

- **Python 3.11+** installed
- **Jupyter notebook** environment set up
- **Hathor development environment** configured (see [docs/developing.md](../docs/developing.md))
- Basic understanding of Python programming
- Familiarity with blockchain concepts (transactions, tokens, smart contracts)

## Running the tutorials

### Starting Jupyter

```bash
# Navigate to the hathor-core-2 directory
cd /path/to/hathor-core-2

# Install dependencies (if not already done)
poetry install

# Start Jupyter notebook
poetry run jupyter notebook nano-tutorials/
```

This will open Jupyter in your browser with the nano-tutorials directory loaded.

### Working with the tutorials

1. Open any tutorial notebook (e.g., `Blueprint.ipynb`)
2. Read through the explanations in the markdown cells
3. Execute code cells one by one using `Shift+Enter`
4. Experiment by modifying the code examples
5. Run the tests to verify your understanding

### Tips

- **Run cells in order**: Some cells depend on previous cells being executed
- **Restart kernel if needed**: If you encounter issues, use `Kernel > Restart & Clear Output`
- **Experiment freely**: The tutorials use isolated test environments, so feel free to modify and experiment
- **Check test output**: Pay attention to test results to understand what's being validated

## Learning path

If you're new to Hathor nanocontracts, we recommend:

1. **Start with Blueprint.ipynb**: Learn the fundamentals of blueprint creation, deposits, withdrawals, and testing
2. **More tutorials coming soon**: Additional tutorials on advanced topics will be added here

## Additional resources

- [Hathor Documentation](https://docs.hathor.network/)
- [Hathor Network Website](https://hathor.network/)
- [Hathor Core Development Guide](../docs/developing.md)
- [Hathor Core Debugging Guide](../docs/debugging.md)

## Contributing

Found an issue or want to improve a tutorial? Contributions are welcome! Please follow the project's contribution guidelines.
