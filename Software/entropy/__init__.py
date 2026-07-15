"""RDRS entropy module package.

Exports the primary public API:
  EntropyMonitor          — event-driven entropy analysis worker
  EntropyIncreaseDetected — alert event dataclass
  calculate_entropy       — pure entropy calculation function
"""

from entropy.monitor import EntropyMonitor, EntropyIncreaseDetected
from entropy.calculator import calculate_entropy

__all__ = ["EntropyMonitor", "EntropyIncreaseDetected", "calculate_entropy"]
