from typing import Optional

from hathor.sysctl.runner import SysctlRunner


class SysctlInitFileLoader:
    def __init__(self, runner: SysctlRunner, init_file: Optional[str]) -> None:
        assert runner

        self.runner = runner
        self.init_file = init_file

    def load(self) -> None:
        if not self.init_file:
            return

        with open(self.init_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        for line in lines:
            self.runner.run(line.strip())
