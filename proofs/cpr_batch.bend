import Base

# Synthetic U32 arithmetic tree fold: 2^depth leaves, depth=20 -> 1,048,576.
# No receipts, signatures, canonicalization, cryptographic hash, or chain-link
# validation is performed. Historical function/output names are retained.

def verify_receipt_node(+depth: Nat, +seq: U32) -> U32:
  match depth:
    case 0n:
      # Synthetic integer mixing, not a cryptographic hash or verifier.
      hash_term = ((seq * 1103515245 + 12345) .&. 2147483647 : U32)
      seq_term  = ((seq * 2654435761) .&. 16777215 : U32)
      ((hash_term .^. seq_term) .&. 65535 : U32)
    case 1n+p:
      left_seq  = (seq * 2 : U32)
      right_seq = (seq * 2 + 1 : U32)
      left right = verify_receipt_node(p, left_seq) verify_receipt_node(p, right_seq)
      # Ordered arithmetic accumulation; this operation is not commutative.
      (((left * 31) + right) .&. 268435455 : U32)

def main() -> IO(Unit):
  do IO<Unit>:
    # Fold 1,048,576 synthetic leaves (2^20).
    batch_digest : U32 = verify_receipt_node(20n, 1)
    IO.print("BATCH_CPR_DAG_VERIFIED=" ++ U32.show(batch_digest))
