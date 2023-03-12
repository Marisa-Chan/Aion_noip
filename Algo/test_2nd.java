import twofish.TwoFish;
import java.util.Arrays;
import java.lang.String;

public class test_2nd{
		final static byte[] staticKey = "nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9".getBytes();
		final static byte[] default2ndKey = {(byte)0x93, (byte)0xd8, 0x2c, (byte)0xf1, (byte)0xe8, 0x03, 0x5a, 0x7d, (byte)0x88, 0x5f, (byte)0xdb, (byte)0xa7, 0x14, (byte)0x9c, (byte)0xbe, 0x63};
		
      public static byte[] RandomizeSecondPwdKey(byte[] xorkey) {
	     byte[] key = default2ndKey.clone();
		 key[0] ^= xorkey[0];
		 
		 for (int i = 1; i < 16; i++)
		    key[i] ^= staticKey[i & 0x3F] ^ xorkey[i & 3] ^ key[i - 1];
		 
		 return key;
	  }
	  
	  public static byte[] RandomizeSecondPwdShuffleKey(byte[] xorkey) {
	     byte[] key = default2ndKey.clone();
		 key[0] ^= xorkey[1];
		 
		 for (int i = 1; i < 16; i++)
		    key[i] ^= staticKey[(16 - i) & 0x3F] ^ xorkey[(i + 1) & 3] ^ key[i - 1];
		 
		 return key;
	  }
	  
	  
	  
	  
      public static void main(String[] args) { 
	  
	    
		byte[] servkey = {(byte)0xee, 0x59, 0x28, (byte)0xd7, (byte)0xa1, 0x6c, 0x54, (byte)0x87};
		byte[] testdata = {(byte)0xe2, 0x22, (byte)0xb5, 0x78, (byte)0xe2, 0x76, 0x36, 0x35, (byte)0xda, (byte)0xf6, 0x2e, (byte)0x69, (byte)0x66, (byte)0x9a, (byte)0xe2, 0x02, 0x57, (byte)0xe9, (byte)0xf7, (byte)0xd7, (byte)0xbb, (byte)0xd3, 0x39, 0x24, (byte)0xb4, 0x17, (byte)0xc3, 0x05, (byte)0x9d, (byte)0x9f, 0x20, (byte)0xf0, 0x21, (byte)0x91, 0x53, (byte)0xbc, 0x53, (byte)0x9c, (byte)0x85, (byte)0xb0, 0x2a, (byte)0xa9, (byte)0xba, 0x17, 0x0f, 0x19, 0x08, 0x2c};
		
		
		byte[] xorkey = Arrays.copyOfRange(servkey, 0, 4);
		
		byte[] SecondPwdKey = RandomizeSecondPwdKey(xorkey);
		byte[] SecondPwdShuffledKey = RandomizeSecondPwdShuffleKey(xorkey);
		
		byte[] decr = new byte[48];
		
		for(int i = 0; i < 3; i++)
			System.arraycopy( TwoFish.decrypt( Arrays.copyOfRange(testdata, i * 16, (i + 1) * 16), SecondPwdKey ), 0, decr, i * 16, 16 );
		
		
		byte[] decr2 = new byte[48];
		
		int strLen = decr[1] ^ SecondPwdShuffledKey[1];
		int multiplier = decr[0] ^ SecondPwdShuffledKey[0];
		
		for (int i = 0; i < strLen; i++) {
			int index = 2 + ((multiplier * (i + 1)) % 43);
			decr2[i] = (byte)(SecondPwdShuffledKey[index & 0xf] ^ decr[index]);
		}
		
		System.out.println( new String(decr2) ); // Or limit decr2 with strLen
      }
}
