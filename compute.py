import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The order of the secp256k1 curve (a large prime number)
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def decompress_signature(signature):
    """Decompress a Bitcoin signature into the standard (r, s) format."""
    # Bitcoin signature (DER encoded) is typically of the format:
    # 0x30 <length> 0x02 <r length> <r> 0x02 <s length> <s>
    if signature[0] != 0x30:
        logger.error("Invalid signature format.")
        return None
    # Extract r and s values
    r_len = signature[3]
    r = signature[4:4+r_len]
    s_len = signature[4+r_len+1]
    s = signature[5+r_len:5+r_len+s_len]
    return int.from_bytes(r, byteorder='big'), int.from_bytes(s, byteorder='big')

def extract_signatures_and_hashes(witness, prev_hash, output_index):
    """Extract and decompress the signature from the witness field, and return the signature and associated message hash."""
    signatures = []
    # Assuming the first element in witness is the signature (DER format)
    signature = bytes.fromhex(witness[0])
    sig = decompress_signature(signature)
    if sig:
        signatures.append(sig)

    # Compute the message hash from prev_hash and output_index
    message = f"{prev_hash}{output_index}".encode('utf-8')
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(message)
    message_digest = message_hash.finalize()

    logger.info(f"Extracted message hash: {message_digest.hex()}")
    
    return signatures, message_digest

def main():
    # Example raw witness data (input it manually)
    witness_data = [
        "3044022074759dcf7f2a879571c77786f99381400741a0108f327b645634803bedb2c7030220543f69df2ed58311d0be8f401c61f10692e3b5cafab4a440d8c3ea42da54f04301",
        "03051b5d771f27ab7564bd86e5c3b1775c6046f594b0e0490936e9a1423a106368"
    ]
    
    prev_hash = "1d26dc6810e3a092e89b039506c93e51c5775ce040f35f2c0f719c380afd5b1c"
    output_index = 24
    
    # Extract signatures and corresponding message hash
    signatures, message_hash = extract_signatures_and_hashes(witness_data, prev_hash, output_index)
    
    if signatures:
        logger.info(f"Extracted signatures: {signatures}")
        logger.info(f"Message hash: {message_hash.hex()}")
        # Use the extracted signatures and message hash in your lattice script
        # Example: matrix = make_matrix([message_hash], signatures, B)
    else:
        logger.warning("No valid signatures found.")

if __name__ == "__main__":
    main()
