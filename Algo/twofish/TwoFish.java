package twofish;

/**
 * @author sala
 */
public class TwoFish {
    private static final byte[][] RS = new byte[][] {
            new byte[] { (byte)0x01, (byte)0xA4, (byte)0x55, (byte)0x87, (byte)0x5A, (byte)0x58, (byte)0xDB, (byte)0x9E},
            new byte[] { (byte)0xA4, (byte)0x56, (byte)0x82, (byte)0xF3, (byte)0x1E, (byte)0xC6, (byte)0x68, (byte)0xE5},
            new byte[] { (byte)0x02, (byte)0xA1, (byte)0xFC, (byte)0xC1, (byte)0x47, (byte)0xAE, (byte)0x3D, (byte)0x19},
            new byte[] { (byte)0xA4, (byte)0x55, (byte)0x87, (byte)0x5A, (byte)0x58, (byte)0xDB, (byte)0x9E, (byte)0x03}
    };
    private static final byte[][] MDS = new byte[][] {
            new byte[] { (byte)0x01, (byte)0xEF, (byte)0x5B, (byte)0x5B},
            new byte[] { (byte)0x5B, (byte)0xEF, (byte)0xEF, (byte)0x01},
            new byte[] { (byte)0xEF, (byte)0x5B, (byte)0x01, (byte)0xEF},
            new byte[] { (byte)0xEF, (byte)0x01, (byte)0xEF, (byte)0x5B},
    };
    private static final byte[] t00 = { 0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4};
    private static final byte[] t01 = { 0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD};
    private static final byte[] t02 = { 0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1};
    private static final byte[] t03 = { 0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA};
    //
    private static final byte[] t10 = { 0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5};
    private static final byte[] t11 = { 0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8};
    private static final byte[] t12 = { 0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF};
    private static final byte[] t13 = { 0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA};

    public static int[] encrypt(int[] plainText, int[] key) {
        return encrypt(plainText, key, false);
    }

    public static int[] encrypt(int[] plainText, int[] key, boolean debug) {
        final int[] roundKey01 = roundKeys(key, 0);
        final int[] roundKey23 = roundKeys(key, 1);
        final int[] roundKey45 = roundKeys(key, 2);
        final int[] roundKey67 = roundKeys(key, 3);
        // whitening
        int[] whitened = whitening(plainText, roundKey01[0], roundKey01[1], roundKey23[0], roundKey23[1]);
        //
        if(debug) {
            System.out.println("whitened:");
            printInternal(whitened);
        }
        //
        for(int i = 0; i < 16; i++) {

            whitened = encryptionRound(whitened, key, i);
            if(debug) {
                System.out.println("R"+i + ":");
                if(i % 2 == 0) {
                    printInternal(whitened);
                }
            }
            whitened = new int[] {whitened[2], whitened[3], whitened[0], whitened[1]};
            if(debug && i % 2 != 0) {
                printInternal(whitened);
            }
        }
        // Swapping
        whitened = new int[] {whitened[2], whitened[3], whitened[0], whitened[1]};
        whitened = whitening(whitened, roundKey45[0], roundKey45[1], roundKey67[0], roundKey67[1]);
        return whitened;
    }
	
	public static byte[] decrypt(byte[] cypheredText, byte[] key) {
        return asBytesBlock(decrypt( fromBytesBlock(cypheredText), fromBytesBlock(key), false));
    }

    public static int[] decrypt(int[] cypheredText, int[] key) {
        return decrypt(cypheredText, key, false);
    }

    public static int[] decrypt(int[] cypheredText, int[] key, boolean debug) {
        if(debug) {
            System.out.println("Cyphered text:");
            printInput(cypheredText);
        }
        final int[] roundKey01 = roundKeys(key, 0);
        final int[] roundKey23 = roundKeys(key, 1);
        final int[] roundKey45 = roundKeys(key, 2);
        final int[] roundKey67 = roundKeys(key, 3);
        // whitening
        int[] whitened = whitening(cypheredText, roundKey45[0], roundKey45[1], roundKey67[0], roundKey67[1]);
        if(debug) {
            System.out.println("Whitened:");
            printInternal(whitened);
        }
        //
        whitened = new int[] {whitened[2], whitened[3], whitened[0], whitened[1]};
        for(int i = 15; i >= 0; i--) {
            whitened = decryptionRound(whitened, key, i);
            if(debug) {
                System.out.println("R"+ (i + 1) + ":");
                if(i % 2 == 0) {
                    printInternal(whitened);
                }
            }
            whitened = new int[] {whitened[2], whitened[3], whitened[0], whitened[1]};
            if(debug && i % 2 != 0) {
                printInternal(whitened);
            }
        }
        whitened = whitening(whitened, roundKey01[0], roundKey01[1], roundKey23[0], roundKey23[1]);
        if(debug) {
        System.out.println("Whitened:");
        printInternal(whitened);
        }
        return whitened;

    }

    public static int[] whitening(int[] plainText, int k0, int k1, int k2, int k3) {
        return new int[] {
                plainText[0] ^ k0,
                plainText[1] ^ k1,
                plainText[2] ^ k2,
                plainText[3] ^ k3
        };
    }

    public static int[] encryptionRound(int[] input, int[] key, int round) {
        final int[] s = getS(key);
        int t0 = h(input[0],                        s[1], s[0]);
        int t1 = h(Integer.rotateLeft(input[1], 8), s[1], s[0]);
        int[] pPht = pht(t0, t1);
        final int[] roundKeys2r_8_2r_9 = roundKeys(key, round + 4);
        //
        final int f0 = pPht[0] + roundKeys2r_8_2r_9[0];
        final int f1 = pPht[1] + roundKeys2r_8_2r_9[1];
        //
        int c2 = Integer.rotateRight((f0 ^ input[2]), 1);
        int c3 = (f1 ^ Integer.rotateLeft(input[3], 1));
        //
        return new int[] { input[0], input[1], c2, c3 };
    }

    public static int[] decryptionRound(int[] input, int[] key, int round) {
        final int[] s = getS(key);
        int t0 = h(input[2],                        s[1], s[0]);
        int t1 = h(Integer.rotateLeft(input[3], 8), s[1], s[0]);
        final int[] pPht = pht(t0, t1);
        final int[] roundKeys = roundKeys(key, round + 4);
        //
        final int f0 = pPht[0] + roundKeys[0];
        final int f1 = pPht[1] + roundKeys[1];
        //
        final int p2 = Integer.rotateLeft(input[0], 1) ^ f0;
        final int p3 = Integer.rotateRight(input[1] ^ f1, 1);
        //
        return new int[] {  p2, p3, input[2], input[3]};

    }

    public static int[] pht(int a, int b) {
        int a1 = a + b;
        int b1 = (a + 2 * b);
        return new int[] {a1, b1};
    }

    public static int h(int input, int l0, int l1) {
        Galua256 galua256 = new Galua256((byte)0b01101001);
        final byte[] x = asBytes(input);
        final byte[] y = asBytes(l1);
        final byte[] z = asBytes(l0);
        final byte[] input11 = new byte[] {
            q1((byte) (q0((byte) (q0(x[0]) ^ y[0])) ^ z[0])),
            q0((byte) (q0((byte) (q1(x[1]) ^ y[1])) ^ z[1])),
            q1((byte) (q1((byte) (q0(x[2]) ^ y[2])) ^ z[2])),
            q0((byte) (q1((byte) (q1(x[3]) ^ y[3])) ^ z[3])),
        };
        return fromBytes(multiply(galua256, MDS, input11));
    }

    public static byte q0(byte input) {
        byte a0 = (byte)((input >> 4) & 0xF);
        byte b0 = (byte)(input & 0xF);
        byte a1 = (byte)(a0 ^ b0);
        byte b1 = (byte)(a0 ^ ((b0 & 1) << 3 | b0 >> 1) ^ ((8*a0) & 0xF));
        byte a2 = t00[a1];
        byte b2 = t01[b1] ;
        byte a3 = (byte)(a2 ^ b2);
        byte b3 = (byte)(a2 ^ ((b2 & 1) << 3 | b2 >> 1) ^ ((8*a2) & 0xF));
        byte a4 = t02[a3];
        byte b4 = t03[b3];
        return (byte)((b4 << 4) | a4);
    }

    public static byte q1(byte input) {
        byte a0 = (byte)((input >> 4) & 0xF);
        byte b0 = (byte)(input & 0xF);
        byte a1 = (byte)(a0 ^ b0);
        byte b1 = (byte)(a0 ^ ((b0 & 1) << 3 | b0 >> 1) ^ ((8*a0) & 0xF));
        byte a2 = t10[a1];
        byte b2 = t11[b1];
        byte a3 = (byte)(a2 ^ b2);
        byte b3 = (byte)(a2 ^ ((b2 & 1) << 3 | b2 >> 1) ^ ((8*a2) & 0xF));
        byte a4 = t12[a3];
        byte b4 = t13[b3];
        return (byte)((b4 << 4) | a4);
    }

    public static int[] getS(int[] key) {
        final int m0 = key[0];
        final int m1 = key[1];
        final int m2 = key[2];
        final int m3 = key[3];
        final int S0 = RS(m0, m1);
        final int S1 = RS(m2, m3);
        return new int[] { S0, S1};
    }

    private static int RS(int X, int Y) {
        byte[] x = asBytes(X);
        byte[] y = asBytes(Y);
        byte[] XY = new byte[8];
        // Merging x and y
        System.arraycopy(x, 0, XY, 0, 4);
        System.arraycopy(y, 0, XY, 4, 4);
        //
        final byte[][] matrix = RS;
        Galua256 galua = new Galua256((byte)0b01001101);
        //
        byte[] S = multiply(galua, matrix, XY);
        return fromBytes(S);
    }

    private static byte[] multiply(Galua256 galua, byte[][] matrix, byte[] vector) {
        byte[] S = new byte[vector.length];
        for(int i = 0; i < matrix.length; i++) {
            final byte[] RSrow = matrix[i];
            S[i] = galua.multiply(RSrow[0], vector[0]);
            for(int j = 1; j < RSrow.length; j++) {
                S[i] = galua.add(S[i], galua.multiply(RSrow[j], vector[j]));
            }
        }
        return S;
    }

    public static int[] roundKeys(int[] key, int round) {
        final int m0 = key[0];
        final int m1 = key[1];
        final int m2 = key[2];
        final int m3 = key[3];
        //
        final int[] Me = new int[] { m0, m2};
        final int[] Mo = new int[] { m1, m3};
        //
        final int rho = (1 << 24) | (1 << 16) | (1 << 8) | 1;
        final int Ai = h(2 * round * rho, Me[0], Me[1]);
        final int Bi = Integer.rotateLeft(h((2 * round + 1) * rho, Mo[0], Mo[1]), 8);
        final int[] pPht = pht(Ai, Bi);
        final int K2i = pPht[0];
        final int K2i_1 = Integer.rotateLeft(pPht[1], 9);
        return new int[] { K2i, K2i_1};
    }

    public static byte[] asBytes(int intValue) {
        return new byte[] {
                (byte)(intValue),
                (byte)(intValue >>> 8),
                (byte)(intValue >>> 16),
                (byte)(intValue >>> 24),
        };
    }

    public static int fromBytes(byte[] bytes) {
        int S0 = 0;
        for(int i = 0; i < 4; i++) {
            S0 |= ((0xFF & bytes[i]) << (i * 8));
        }
        return S0;
    }
	
	public static int[] fromBytesBlock(byte[] bytes) {
        int[] S = {0, 0, 0, 0};
        for(int i = 0; i < 16 && i < bytes.length; i++) {			
            S[i >> 2] |= ((0xFF & bytes[i]) << ((i & 3) * 8));
        }
        return S;
    }
	
	public static byte[] asBytesBlock(int[] intValue) {
        return new byte[] {
                (byte)(intValue[0]),
                (byte)(intValue[0] >>> 8),
                (byte)(intValue[0] >>> 16),
                (byte)(intValue[0] >>> 24),
				(byte)(intValue[1]),
                (byte)(intValue[1] >>> 8),
                (byte)(intValue[1] >>> 16),
                (byte)(intValue[1] >>> 24),
				(byte)(intValue[2]),
                (byte)(intValue[2] >>> 8),
                (byte)(intValue[2] >>> 16),
                (byte)(intValue[2] >>> 24),
				(byte)(intValue[3]),
                (byte)(intValue[3] >>> 8),
                (byte)(intValue[3] >>> 16),
                (byte)(intValue[3] >>> 24),
        };
    }
	
	private static void printInput(int[] plainText) {
        for(int i = 0; i <= 3; i++) {
            for(byte b  : TwoFish.asBytes(plainText[i])) {
                System.out.print(String.format("%02X", b));
            }
        }
        System.out.println();
    }

    private static void printInternal(int[] whitened) {
        for(int whitenedEntry : whitened) {
            System.out.print(String.format("%02X", whitenedEntry));
        }
        System.out.println();
    }
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/**
	 * @author sala
	 */
	static public class Galua256 {
		private final byte mask;
		public Galua256(byte mask) {
			this.mask = mask;
		}

		public byte add(byte a, byte b) {
			return (byte)(a ^ b);
		}

		public byte add(byte a, byte... b) {
			byte sum = a;
			for (byte aB : b) {
				sum = add(sum, aB);
			}
			return sum;
		}

		public byte multiply(byte a, byte b) {
			byte p = 0;

			for(int i = 0; i < 8; i++) {
				if((b & 1) != 0) {
					p ^= a;
				}
				byte carry = (byte)(a & 0x80);
				a <<= 1;
				if(carry != 0) {
					a ^= mask;
				}
				b >>= 1;
			}
			return p;
		}
	}
}