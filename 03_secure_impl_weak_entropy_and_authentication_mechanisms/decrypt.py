#!/usr/bin/env python3

import random
import sys
from Crypto.Cipher import AES
from datetime import datetime, timedelta


def try_decrypt(ciphertext_file, timestamp):
    """Try to decrypt with a given timestamp seed."""
    try:
        with open(ciphertext_file, 'rb') as f:
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        
        # Recreate the key with the given timestamp
        random.seed(int(timestamp))
        key = random.randbytes(16)
        
        # Try to decrypt
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = aes.decrypt_and_verify(ciphertext, tag)
        
        return plaintext
    except ValueError:
        # GCM tag verification failed
        return None
    except Exception as e:
        return None


def brute_force_decrypt(ciphertext_file, start_date, num_days=7):
    """Brute force decrypt by trying timestamps in a range."""
    
    # Convert date to timestamp
    start_timestamp = int(start_date.timestamp())
    
    print(f"Brute forcing timestamps from {start_date} to {start_date + timedelta(days=num_days)}")
    print(f"That's {num_days * 86400} possible timestamps to try...")
    
    attempts = 0
    for day_offset in range(num_days):
        for second_in_day in range(86400):
            timestamp = start_timestamp + day_offset * 86400 + second_in_day
            
            plaintext = try_decrypt(ciphertext_file, timestamp)
            attempts += 1
            
            if plaintext is not None:
                print(f"\n✓ SUCCESS! Found the key after {attempts} attempts")
                print(f"Timestamp: {datetime.utcfromtimestamp(timestamp)} UTC")
                print(f"Decrypted plaintext:")
                print(plaintext.decode('utf-8', errors='replace'))
                return plaintext
            
            if attempts % 10000 == 0:
                current_time = datetime.utcfromtimestamp(timestamp)
                print(f"Tried {attempts} timestamps... currently at {current_time} UTC")
    
    print(f"Failed to decrypt after {attempts} attempts")
    return None


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'usage: {sys.argv[0]} <ciphertext-file> [start_date] [num_days]')
        print(f'  start_date format: YYYY-MM-DD (default: 7 days ago)')
        print(f'  num_days: number of days to brute force (default: 7)')
        exit(1)
    
    ciphertext_file = sys.argv[1]
    
    # Default: try 7 days starting from 7 days ago
    if len(sys.argv) >= 3:
        start_date = datetime.strptime(sys.argv[2], '%Y-%m-%d')
    else:
        start_date = datetime.utcnow() - timedelta(days=7)
    
    num_days = int(sys.argv[3]) if len(sys.argv) >= 4 else 7
    
    brute_force_decrypt(ciphertext_file, start_date, num_days)
