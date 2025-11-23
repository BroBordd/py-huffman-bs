#!/usr/bin/env python3
"""
huffman_bs.py - BombSquad/Ballistica Network Packet Huffman Codec

This tool decompresses and compresses Huffman-encoded network packets used in
BombSquad (Ballistica engine). It can decode captured packets to understand their
structure and create new packets for testing or modding.

The Huffman encoding uses a static frequency table built from captured game traffic
to achieve ~40-60% compression on typical game packets.

Usage:
    # Decode a packet
    codec = HuffmanCodec()
    decompressed = codec.decompress(compressed_bytes)
    
    # Encode a packet
    compressed = codec.compress(scene_packet_bytes)
    full_packet = codec.encode_full_packet(scene_packet_bytes, client_id=0x7c)

Based on Ballistica source code:
    src/ballistica/scene_v1/support/huffman.cc
    src/ballistica/base/networking/networking.h
"""

# ============================================================================
# PACKET TYPE DEFINITIONS (from networking.h)
# ============================================================================

# Raw UDP packet types (first byte of packet)
BA_PACKET_REMOTE_PING = 0
BA_PACKET_REMOTE_PONG = 1
BA_PACKET_REMOTE_ID_REQUEST = 2
BA_PACKET_REMOTE_ID_RESPONSE = 3
BA_PACKET_REMOTE_DISCONNECT = 4
BA_PACKET_REMOTE_STATE = 5
BA_PACKET_REMOTE_STATE_ACK = 6
BA_PACKET_REMOTE_DISCONNECT_ACK = 7
BA_PACKET_REMOTE_GAME_QUERY = 8
BA_PACKET_REMOTE_GAME_RESPONSE = 9
BA_PACKET_REMOTE_STATE2 = 10
BA_PACKET_SIMPLE_PING = 11
BA_PACKET_SIMPLE_PONG = 12
BA_PACKET_JSON_PING = 13
BA_PACKET_JSON_PONG = 14
BA_PACKET_POKE = 21
BA_PACKET_HOST_QUERY = 22
BA_PACKET_HOST_QUERY_RESPONSE = 23
BA_PACKET_CLIENT_REQUEST = 24
BA_PACKET_CLIENT_ACCEPT = 25
BA_PACKET_CLIENT_DENY = 26
BA_PACKET_CLIENT_DENY_VERSION_MISMATCH = 27
BA_PACKET_CLIENT_DENY_ALREADY_IN_PARTY = 28
BA_PACKET_CLIENT_DENY_PARTY_FULL = 29
BA_PACKET_DISCONNECT_FROM_CLIENT_REQUEST = 32
BA_PACKET_DISCONNECT_FROM_CLIENT_ACK = 33
BA_PACKET_DISCONNECT_FROM_HOST_REQUEST = 34
BA_PACKET_DISCONNECT_FROM_HOST_ACK = 35
BA_PACKET_CLIENT_GAMEPACKET_COMPRESSED = 36
BA_PACKET_HOST_GAMEPACKET_COMPRESSED = 37

# Scene packet types (first byte after decompression)
# These are game-level packets that sit inside the compressed UDP packets
BA_SCENEPACKET_HANDSHAKE = 15
BA_SCENEPACKET_HANDSHAKE_RESPONSE = 16
BA_SCENEPACKET_MESSAGE = 17
BA_SCENEPACKET_MESSAGE_UNRELIABLE = 18
BA_SCENEPACKET_DISCONNECT = 19
BA_SCENEPACKET_KEEPALIVE = 20

# Message types (high-level game messages)
# These are the actual game commands/data inside scene packets
BA_MESSAGE_SESSION_RESET = 0
BA_MESSAGE_SESSION_COMMANDS = 1
BA_MESSAGE_SESSION_DYNAMICS_CORRECTION = 2
BA_MESSAGE_NULL = 3
BA_MESSAGE_REQUEST_REMOTE_PLAYER = 4
BA_MESSAGE_ATTACH_REMOTE_PLAYER = 5  # OBSOLETE
BA_MESSAGE_DETACH_REMOTE_PLAYER = 6
BA_MESSAGE_REMOTE_PLAYER_INPUT_COMMANDS = 7
BA_MESSAGE_REMOVE_REMOTE_PLAYER = 8
BA_MESSAGE_PARTY_ROSTER = 9
BA_MESSAGE_CHAT = 10
BA_MESSAGE_PARTY_MEMBER_JOINED = 11
BA_MESSAGE_PARTY_MEMBER_LEFT = 12
BA_MESSAGE_MULTIPART = 13
BA_MESSAGE_MULTIPART_END = 14
BA_MESSAGE_CLIENT_PLAYER_PROFILES = 15
BA_MESSAGE_ATTACH_REMOTE_PLAYER_2 = 16
BA_MESSAGE_HOST_INFO = 17
BA_MESSAGE_CLIENT_INFO = 18
BA_MESSAGE_KICK_VOTE = 19
BA_MESSAGE_JMESSAGE = 20
BA_MESSAGE_CLIENT_PLAYER_PROFILES_JSON = 21

# JSON message sub-types
BA_JMESSAGE_SCREEN_MESSAGE = 0

# Lookup dictionaries for pretty printing
PACKET_TYPES = {
    0: "BA_PACKET_REMOTE_PING",
    1: "BA_PACKET_REMOTE_PONG",
    2: "BA_PACKET_REMOTE_ID_REQUEST",
    3: "BA_PACKET_REMOTE_ID_RESPONSE",
    4: "BA_PACKET_REMOTE_DISCONNECT",
    5: "BA_PACKET_REMOTE_STATE",
    6: "BA_PACKET_REMOTE_STATE_ACK",
    7: "BA_PACKET_REMOTE_DISCONNECT_ACK",
    8: "BA_PACKET_REMOTE_GAME_QUERY",
    9: "BA_PACKET_REMOTE_GAME_RESPONSE",
    10: "BA_PACKET_REMOTE_STATE2",
    11: "BA_PACKET_SIMPLE_PING",
    12: "BA_PACKET_SIMPLE_PONG",
    13: "BA_PACKET_JSON_PING",
    14: "BA_PACKET_JSON_PONG",
    21: "BA_PACKET_POKE",
    22: "BA_PACKET_HOST_QUERY",
    23: "BA_PACKET_HOST_QUERY_RESPONSE",
    24: "BA_PACKET_CLIENT_REQUEST",
    25: "BA_PACKET_CLIENT_ACCEPT",
    26: "BA_PACKET_CLIENT_DENY",
    27: "BA_PACKET_CLIENT_DENY_VERSION_MISMATCH",
    28: "BA_PACKET_CLIENT_DENY_ALREADY_IN_PARTY",
    29: "BA_PACKET_CLIENT_DENY_PARTY_FULL",
    32: "BA_PACKET_DISCONNECT_FROM_CLIENT_REQUEST",
    33: "BA_PACKET_DISCONNECT_FROM_CLIENT_ACK",
    34: "BA_PACKET_DISCONNECT_FROM_HOST_REQUEST",
    35: "BA_PACKET_DISCONNECT_FROM_HOST_ACK",
    36: "BA_PACKET_CLIENT_GAMEPACKET_COMPRESSED",
    37: "BA_PACKET_HOST_GAMEPACKET_COMPRESSED",
}

SCENEPACKET_TYPES = {
    15: "BA_SCENEPACKET_HANDSHAKE",
    16: "BA_SCENEPACKET_HANDSHAKE_RESPONSE",
    17: "BA_SCENEPACKET_MESSAGE",
    18: "BA_SCENEPACKET_MESSAGE_UNRELIABLE",
    19: "BA_SCENEPACKET_DISCONNECT",
    20: "BA_SCENEPACKET_KEEPALIVE",
}

MESSAGE_TYPES = {
    0: "BA_MESSAGE_SESSION_RESET",
    1: "BA_MESSAGE_SESSION_COMMANDS",
    2: "BA_MESSAGE_SESSION_DYNAMICS_CORRECTION",
    3: "BA_MESSAGE_NULL",
    4: "BA_MESSAGE_REQUEST_REMOTE_PLAYER",
    5: "BA_MESSAGE_ATTACH_REMOTE_PLAYER",
    6: "BA_MESSAGE_DETACH_REMOTE_PLAYER",
    7: "BA_MESSAGE_REMOTE_PLAYER_INPUT_COMMANDS",
    8: "BA_MESSAGE_REMOVE_REMOTE_PLAYER",
    9: "BA_MESSAGE_PARTY_ROSTER",
    10: "BA_MESSAGE_CHAT",
    11: "BA_MESSAGE_PARTY_MEMBER_JOINED",
    12: "BA_MESSAGE_PARTY_MEMBER_LEFT",
    13: "BA_MESSAGE_MULTIPART",
    14: "BA_MESSAGE_MULTIPART_END",
    15: "BA_MESSAGE_CLIENT_PLAYER_PROFILES",
    16: "BA_MESSAGE_ATTACH_REMOTE_PLAYER_2",
    17: "BA_MESSAGE_HOST_INFO",
    18: "BA_MESSAGE_CLIENT_INFO",
    19: "BA_MESSAGE_KICK_VOTE",
    20: "BA_MESSAGE_JMESSAGE",
    21: "BA_MESSAGE_CLIENT_PLAYER_PROFILES_JSON",
}

# ============================================================================
# HUFFMAN CODEC IMPLEMENTATION
# ============================================================================

# Static frequency table built from captured BombSquad network traffic
# This is used to build the Huffman tree for compression/decompression
G_FREQS = [
    101342, 9667, 3497, 1072, 0, 3793, 0, 0, 2815, 5235, 0, 0, 0, 3570, 0, 0,
    0, 1383, 0, 0, 0, 2970, 0, 0, 2857, 0, 0, 0, 0, 0, 0, 0,
    0, 1199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1494,
    1974, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1351, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1475,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
]


class Node:
    """Huffman tree node for encoding/decoding"""
    def __init__(self):
        self.left_child = -1      # Index of left child node (-1 = none)
        self.right_child = -1     # Index of right child node (-1 = none)
        self.parent = 0           # Parent index (0 = none, add 255 for actual index)
        self.bits = 0             # Number of bits in encoded value
        self.val = 0              # Encoded bit pattern
        self.frequency = 0        # Frequency count for tree building


class HuffmanCodec:
    """
    Huffman codec for BombSquad/Ballistica network packets.
    
    Implements the same Huffman compression algorithm used by the game engine.
    The codec uses a pre-built frequency table from captured game traffic.
    
    Key features:
    - Compresses only if result is smaller than original
    - Uses high bit of first byte as compression flag (1 = compressed)
    - Supports both Huffman-encoded and raw 8-bit values in bitstream
    """
    
    def __init__(self):
        """Initialize codec and build Huffman tree"""
        self.nodes = [Node() for _ in range(511)]
        self.build()
    
    def build(self):
        """
        Build Huffman tree from frequency table.
        
        Creates a 511-node tree where:
        - Nodes 0-255: Leaf nodes representing bytes
        - Nodes 256-510: Internal nodes
        - Node 510: Root node
        """
        # Initialize leaf node frequencies
        for i in range(256):
            self.nodes[i].frequency = G_FREQS[i]
        
        node_count = 256
        
        # Build tree by repeatedly combining two smallest nodes
        while node_count < 511:
            # Find first two non-parented nodes
            i = 0
            while self.nodes[i].parent != 0:
                i += 1
            smallest1 = i
            i += 1
            while self.nodes[i].parent != 0:
                i += 1
            smallest2 = i
            i += 1
            
            # Find the two smallest frequencies
            while i < node_count:
                if self.nodes[i].parent == 0:
                    if self.nodes[smallest1].frequency > self.nodes[smallest2].frequency:
                        if self.nodes[i].frequency < self.nodes[smallest1].frequency:
                            smallest1 = i
                    else:
                        if self.nodes[i].frequency < self.nodes[smallest2].frequency:
                            smallest2 = i
                i += 1
            
            # Create parent node
            self.nodes[node_count].frequency = (
                self.nodes[smallest1].frequency + self.nodes[smallest2].frequency
            )
            self.nodes[smallest1].parent = node_count - 255
            self.nodes[smallest2].parent = node_count - 255
            self.nodes[node_count].right_child = smallest1
            self.nodes[node_count].left_child = smallest2
            
            node_count += 1
        
        # Build encoding bit patterns for each byte value
        for i in range(256):
            self.nodes[i].val = 0
            self.nodes[i].bits = 0
            index = i
            
            # Walk up tree to build bit pattern
            while self.nodes[index].parent != 0:
                parent_idx = self.nodes[index].parent + 255
                # Right child = 1, left child = 0
                if self.nodes[parent_idx].right_child == index:
                    self.nodes[i].val = (self.nodes[i].val << 1) | 0x01
                else:
                    self.nodes[i].val = self.nodes[i].val << 1
                self.nodes[i].bits += 1
                index = parent_idx
            
            # Add prefix bit: 1 = huffman encoded, 0 = raw 8-bit value
            # If huffman encoding would be >= 8 bits, just use raw value
            if self.nodes[i].bits >= 8:
                self.nodes[i].bits = 8
                self.nodes[i].val = i << 1  # Raw value with 0 prefix
            else:
                self.nodes[i].val = (self.nodes[i].val << 1) | 0x01  # Huffman with 1 prefix
            self.nodes[i].bits += 1
    
    def write_bits(self, output, bit_pos, val, val_bits):
        """
        Write bits to output buffer.
        
        Args:
            output: List of bytes to write to
            bit_pos: Current bit position in output
            val: Value to write
            val_bits: Number of bits to write
            
        Returns:
            New bit position after writing
        """
        src_bit = 0
        while src_bit < val_bits:
            byte_idx = bit_pos // 8
            bit_in_byte = bit_pos % 8
            
            # Ensure buffer is large enough
            while len(output) <= byte_idx:
                output.append(0)
            
            # Write one bit
            if (val >> src_bit) & 1:
                output[byte_idx] |= (1 << bit_in_byte)
            
            bit_pos += 1
            src_bit += 1
        
        return bit_pos
    
    def compress(self, data):
        """
        Compress data using Huffman encoding.
        
        Args:
            data: Raw bytes to compress
            
        Returns:
            Compressed bytes (or original if compression doesn't help)
            
        Raises:
            ValueError: If first byte has high bit set (reserved for compression flag)
        """
        if len(data) == 0:
            return bytes()
        
        # First byte must have high bit clear (used for compression flag)
        if data[0] & 0x80:
            raise ValueError("First byte must have high bit clear (required for compression flag)")
        
        # Calculate total bits needed
        bit_count = 0
        for byte in data:
            bit_count += self.nodes[byte].bits
        
        # Calculate output size
        length_out = (bit_count + 7) // 8 + 1  # Round up + 1 byte header
        remainder = bit_count % 8
        
        # If compression doesn't help, return original
        if length_out >= len(data):
            return data
        
        # Build compressed output
        output = [0]  # Header byte
        bit_pos = 8   # Start after header
        
        for byte in data:
            bit_pos = self.write_bits(output, bit_pos, 
                                     self.nodes[byte].val, 
                                     self.nodes[byte].bits)
        
        # Set header: low 4 bits = unused trailing bits, high bit = compressed flag
        output[0] = (8 - remainder % 8) if remainder else 0
        output[0] |= 0x80  # Mark as compressed
        
        return bytes(output)
    
    def decompress(self, data):
        """
        Decompress Huffman-encoded data.
        
        Args:
            data: Compressed bytes
            
        Returns:
            Decompressed bytes
            
        Raises:
            ValueError: If data is malformed
        """
        if len(data) == 0:
            raise ValueError("Empty data")
        
        # Read header
        remainder = data[0] & 0x0F
        compressed = (data[0] >> 7) & 1
        
        if not compressed:
            # Not compressed, return as-is
            return data
        
        # Calculate bit length
        bit_length = (len(data) - 1) * 8
        if remainder > bit_length:
            raise ValueError("Invalid huffman data: remainder > bit_length")
        bit_length -= remainder
        
        out = []
        bit = 0
        ptr_offset = 1  # Skip header byte
        
        # Decode bit by bit
        while bit < bit_length:
            # Read prefix bit
            bitval = (data[ptr_offset + bit // 8] >> (bit % 8)) & 1
            bit += 1
            
            if bitval:
                # Huffman-encoded value: walk tree
                n = 510  # Start at root
                while True:
                    bitval = (data[ptr_offset + bit // 8] >> (bit % 8)) & 1
                    
                    # Navigate tree: 0 = left, 1 = right
                    if bitval == 0:
                        if self.nodes[n].left_child == -1:
                            val = n
                            break
                        else:
                            n = self.nodes[n].left_child
                            bit += 1
                    else:
                        if self.nodes[n].right_child == -1:
                            val = n
                            break
                        else:
                            n = self.nodes[n].right_child
                            bit += 1
                    
                    # Detect dead-end nodes
                    if self.nodes[n].left_child == -1 and self.nodes[n].right_child == -1:
                        val = n
                        break
                    
                    if bit > bit_length:
                        raise ValueError("Bit position exceeded bit_length during huffman decode")
                
                out.append(val & 0xFF)
            else:
                # Raw 8-bit value
                if bit % 8 == 0:
                    val = data[ptr_offset + bit // 8]
                else:
                    val = (data[ptr_offset + bit // 8] >> (bit % 8)) | \
                          (data[ptr_offset + bit // 8 + 1] << (8 - bit % 8))
                out.append(val & 0xFF)
                bit += 8
                
                if bit > bit_length:
                    raise ValueError("Bit position exceeded bit_length during raw read")
        
        return bytes(out)
    
    def encode_full_packet(self, scene_packet_data, client_id=0x7c):
        """
        Encode a complete network packet with header and compression.
        
        Creates a full UDP packet ready to send, consisting of:
        [packet_type] [client_id] [compressed_scene_packet_data]
        
        Args:
            scene_packet_data: Raw scene packet bytes to encode
            client_id: Client ID byte (default 0x7c = 124)
            
        Returns:
            Complete packet bytes ready to send
        """
        # Compress the scene packet
        compressed = self.compress(scene_packet_data)
        
        # Add packet header
        full_packet = bytes([BA_PACKET_CLIENT_GAMEPACKET_COMPRESSED, client_id]) + compressed
        return full_packet


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def decode_packet(hex_string, verbose=True):
    """
    Decode and display a packet from hex string.
    
    Args:
        hex_string: Space-separated hex bytes (e.g. "24 7c 87 f5 66")
        verbose: Print detailed information
        
    Returns:
        Decompressed scene packet bytes, or None on error
    """
    # Parse hex
    hex_clean = hex_string.replace(" ", "")
    data = bytes.fromhex(hex_clean)
    
    if verbose:
        print(f"Raw packet ({len(data)} bytes): {data.hex(' ')}")
        print(f"Packet type: 0x{data[0]:02x} ({PACKET_TYPES.get(data[0], 'UNKNOWN')})")
        print(f"Client ID: 0x{data[1]:02x}")
    
    # Decompress payload
    compressed_data = data[2:]
    codec = HuffmanCodec()
    
    try:
        decompressed = codec.decompress(compressed_data)
        if verbose:
            print(f"\nDecompressed ({len(decompressed)} bytes): {decompressed.hex(' ')}")
            print(f"Compression ratio: {len(compressed_data)}/{len(decompressed)} = {len(compressed_data)/len(decompressed)*100:.1f}%")
            print(f"Scene packet type: 0x{decompressed[0]:02x} ({SCENEPACKET_TYPES.get(decompressed[0], 'UNKNOWN')})")
            
            # Try to decode message type
            if decompressed[0] == BA_SCENEPACKET_MESSAGE and len(decompressed) >= 7:
                message_type = decompressed[6]
                print(f"Message type: 0x{message_type:02x} ({MESSAGE_TYPES.get(message_type, 'UNKNOWN')})")
                print(f"Message data: {decompressed[7:].hex(' ')}")
            elif decompressed[0] == BA_SCENEPACKET_MESSAGE_UNRELIABLE and len(decompressed) >= 9:
                message_type = decompressed[8]
                print(f"Message type: 0x{message_type:02x} ({MESSAGE_TYPES.get(message_type, 'UNKNOWN')})")
                print(f"Message data: {decompressed[9:].hex(' ')}")
        
        return decompressed
    except Exception as e:
        if verbose:
            print(f"Error decompressing: {e}")
        return None


def encode_packet(scene_packet_hex, client_id=0x7c, verbose=True):
    """
    Encode a scene packet into a full compressed packet.
    
    Args:
        scene_packet_hex: Scene packet as hex string
        client_id: Client ID byte
        verbose: Print detailed information
        
    Returns:
        Full encoded packet bytes
    """
    hex_clean = scene_packet_hex.replace(" ", "")
    scene_data = bytes.fromhex(hex_clean)
    
    codec = HuffmanCodec()
    full_packet = codec.encode_full_packet(scene_data, client_id)
    
    if verbose:
        print(f"Scene packet ({len(scene_data)} bytes): {scene_data.hex(' ')}")
        print(f"Full packet ({len(full_packet)} bytes): {full_packet.hex(' ')}")
        print(f"Compression ratio: {len(full_packet)-2}/{len(scene_data)} = {(len(full_packet)-2)/len(scene_data)*100:.1f}%")
    
    return full_packet


# ============================================================================
# MAIN / TESTING
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("BombSquad/Ballistica Huffman Packet Codec")
    print("=" * 70)
    
    # Test with captured packets
    print("\n" + "=" * 70)
    print("PUNCH PRESS PACKET:")
    print("=" * 70)
    press_data = decode_packet("24 7c 87 f5 66 47 ed 0e c6 f0 00 8b 0c fe 01")
    
    print("\n" + "=" * 70)
    print("PUNCH RELEASE PACKET:")
    print("=" * 70)
    release_data = decode_packet("24 7c 80 75 0e 9b 6a 77 30 86 7f 07 ff")
    
    # Test re-encoding
    if press_data:
        print("\n" + "=" * 70)
        print("RE-ENCODE TEST (should match original):")
        print("=" * 70)
        original = bytes.fromhex("24 7c 87 f5 66 47 ed 0e c6 f0 00 8b 0c fe 01".replace(" ", ""))
        reencoded = encode_packet(press_data.hex(), verbose=False)
        print(f"Original:  {original.hex(' ')}")
        print(f"Reencoded: {reencoded.hex(' ')}")
        print(f"Match: {reencoded == original}")
