import hashlib
import json
from datetime import datetime
from config import Config

class Block:
    """Represents a single block in the chain."""
    def __init__(self, index, data, previous_hash, nonce=0, timestamp=None):
        self.index = index
        self.timestamp = timestamp or datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        self.data = data # This is a JSON string of the transaction
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        """Computes the SHA-512 hash for the block, mandated by the paper."""
        # The data to be hashed must be consistent and ordered
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        
        # Use SHA-512, as mandated
        return hashlib.sha512(block_string.encode()).hexdigest()

class Blockchain:
    """Manages the chain and block validation."""
    def __init__(self):
        self.chain = []
        self.difficulty = Config.DIFFICULTY
        
        if not self.chain:
            self._create_genesis_block()

    def _create_genesis_block(self):
        """Creates the initial block of the chain."""
        genesis_block = Block(
            index=0, 
            data=json.dumps({"message": "Genesis Block of Secure Banking System"}),
            previous_hash="0" * 128 # 128 chars for SHA-512 zero padding
        )
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        """Returns the last block in the chain."""
        return self.chain[-1] if self.chain else None

    def proof_of_work(self, block):
        """Simple Proof-of-Work algorithm: Find a hash that meets the difficulty requirement."""
        block.nonce = 0
        target_prefix = '0' * self.difficulty
        
        while True:
            computed_hash = block.compute_hash()
            if computed_hash.startswith(target_prefix):
                return computed_hash, block.nonce
            block.nonce += 1

    def add_block(self, new_block, nonce):
        """Adds a new block to the chain after successful mining/validation."""
        new_block.hash = new_block.compute_hash()
        new_block.nonce = nonce
        self.chain.append(new_block)

    def mine_new_transaction(self, data):
        """Wrapper to create a new block and mine it."""
        last_block = self.last_block

        # 🔥 --- CORRECTION WAS HERE ---
        # The 'data' variable is already an encrypted string from app.py.
        # We must NOT wrap it in json.dumps() again.
        new_block = Block(
            index=last_block.index + 1,
            data=data, # Removed json.dumps(data)
            previous_hash=last_block.hash
        )
        
        mined_hash, nonce = self.proof_of_work(new_block)
        
        self.add_block(new_block, nonce)
        
        return new_block

    def is_chain_valid(self):
        """Checks the integrity of the entire chain."""
        # Iterate from the second block (index 1)
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # 1. Check if the block's stored hash is correct by re-computing
            if current_block.hash != current_block.compute_hash():
                print(f"Integrity Error: Block {i} computed hash does not match stored hash.")
                return False
            
            # 2. Check if the previous hash link is correct
            if current_block.previous_hash != previous_block.hash:
                print(f"Integrity Error: Block {i} previous_hash does not match Block {i-1} hash.")
                return False
            
            # 3. Check Proof of Work (that the hash is valid)
            if not current_block.hash.startswith('0' * self.difficulty):
                print(f"Integrity Error: Block {i} hash does not meet PoW difficulty.")
                return False
                
        # If all blocks pass, the chain is valid
        return True