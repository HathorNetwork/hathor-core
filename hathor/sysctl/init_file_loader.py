from hathor.sysctl.runner import SysctlRunner


class SysctlInitFileLoader:
    def __init__(self, runner: SysctlRunner, init_file: str) -> None:
        assert runner
        assert init_file

        self.runner = runner
        self.init_file = init_file

    def load(self) -> None:
        """Read the init_file and execute each line as a syctl command in the runner."""
        with open(self.init_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        for line in lines:
            self.runner.run(line.strip())
