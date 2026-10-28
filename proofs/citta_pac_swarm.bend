import Base

# Synthetic U32 arithmetic tree fold in Bend.
# depth=22 -> 4,194,304 leaves / 8,388,607 tree nodes. Leaves are arithmetic
# evaluations, not running agents. No reservations or conflict checks occur.
def swarm_arbitrate(+depth: Nat, +seed: U32) -> U32:
  match depth:
    case 0n:
      seal_1792 = ((seed * 747796405 + 2891336453) .&. 2047 : U32)
      utility   = ((seed * 1664525 + 1013904223) .&. 4095 : U32)
      ((seal_1792 + utility) .&. 65535 : U32)
    case 1n+p:
      left_seed  = (seed * 2 + 1 : U32)
      right_seed = (seed * 2 + 2 : U32)
      a b = swarm_arbitrate(p, left_seed) swarm_arbitrate(p, right_seed)
      ((a + b) .&. 268435455 : U32)

def main() -> IO(Unit):
  do IO<Unit>:
    res : U32 = swarm_arbitrate(22n, 1)
    IO.print("SWARM_WARRANT_DIGEST=" ++ U32.show(res))
