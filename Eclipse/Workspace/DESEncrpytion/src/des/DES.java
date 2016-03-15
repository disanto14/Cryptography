package des;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Arrays;
import java.util.BitSet;

public class DES {

	private int[] initialPermutation = {
			58,50,42,34,26,18,10,2,
			60,52,44,36,28,20,12,4,
			62,54,46,38,30,22,14,6,
			64,56,48,40,32,24,16,8,
			57,49,41,33,25,17,9,1,
			59,51,43,35,27,19,11,3,
			61,53,45,37,29,21,13,5,
			63,55,47,39,31,23,15,7};

	private int[] expansionFunction = {
			32,1,2,3,4,5,4,5,6,7,8,9,
			8,9,10,11,12,13,12,13,14,15,16,17,
			16,17,18,19,20,21,20,21,22,23,24,25,
			24,25,26,27,28,29,28,29,30,31,32,1};

	private int[] stringPermutation = {
			16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
			2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};

	private int[] keyPermutation = {
			57,49,41,33,25,17,9,1,58,50,42,34,26,18,
			10,2,59,51,43,35,27,19,11,3,60,52,44,36,
			63,55,47,39,31,23,15,7,62,54,46,38,30,22,
			14,6,61,53,45,37,29,21,13,5,28,20,12,4};

	private static int[] keyBitShift = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

	private int[] keySelection = {
			14,17,11,24,1,5,3,28,15,6,21,10,
			23,19,12,4,26,8,16,7,27,20,13,2,
			41,52,31,37,47,55,30,40,51,45,33,48,
			44,49,39,56,34,53,46,42,50,36,29,32};

	private byte[] key;
	private BitSet[] keys;
	private int[][][] sBoxes;

	public DES(byte[] key) {
		this.key = key;
		validateKey();
		readSBoxes();
		convertArraysToZeroIndexing();
		generateKeys();
	}

	private void readSBoxes() {
		sBoxes = new int[8][4][16];
		for (int box = 0; box < sBoxes.length; box++) {
			for (int line = 0; line < sBoxes[box].length; line++) {
				for (int i = 0; i < sBoxes[box][line].length; i++) {
					sBoxes[box][line][i] = 0;
				}
			}
		}
		try {
			FileReader sBoxesReader = new FileReader("src/des/SBoxes");
			BufferedReader sBoxesBuffer = new BufferedReader(sBoxesReader);
			String line = null;
			int l = 0;
			int i = 0;
			while ((line = sBoxesBuffer.readLine()) != null) {
				if (l % 5 != 4) {
					String[] entries = line.split(" ");
					for (String e: entries) {
						sBoxes[l/5][l%5][i++] = Integer.parseInt(e);
					}
				}
				l++;
				i = 0;		
			}
			sBoxesBuffer.close();
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}

	private void validateKey() {
		System.out.println("Original key:");
		for (int i = 0; i < key.length; i++)
			System.out.print(formatByte(key[i]) + " ");
		byte[] newKey = new byte[8];
		for (int i = 0; i < 8; i++) {
			int x = 1;
			if (i < key.length) {
				x = Byte.toUnsignedInt(key[i]);
				if (Integer.bitCount(x)% 2 == 0)
					x ^= 1;
			}
			newKey[i] = (byte)x;
		}
		key = newKey;
		System.out.println("\nFixed parity key:");
		for (int i = 0; i < key.length; i++)
			System.out.print(formatByte(key[i]) + " ");
	}

	private void convertArraysToZeroIndexing() {
		for (int i = 0; i < initialPermutation.length; i++) {
			initialPermutation[i] -= 1;
		}
		for (int i = 0; i < expansionFunction.length; i++) {
			expansionFunction[i] -= 1;
		}
		for (int i = 0; i < stringPermutation.length; i++) {
			stringPermutation[i] -= 1;
		}
		for (int i = 0; i < keySelection.length; i++) {
			keySelection[i] -= 1;
		}
		for (int i = 0; i < keyPermutation.length; i++) {
			keyPermutation[i] -= 1;
		}
	}

	private void generateKeys() {
		keys = new BitSet[16];
		BitSet k = BitSet.valueOf(key);
		//		System.out.println("Original Key: " + k + "\n");
		BitSet newK = new BitSet(56);
		for (int i = 0; i < 56; i++) {
			newK.set(i, k.get(keyPermutation[i]));
		}
		//		System.out.println("Permuted Reduced Key: " + newK + "\n");
		BitSet c = newK.get(0, 28);
		BitSet d = newK.get(28, 56);
		for (int i = 0; i < 16; i++) {
			int s = keyBitShift[i];
			for (int j = 0; j < 28 - s; j++) {
				c.set(i, c.get(i+s));
				c.set(28-s-1, 28, false);
				d.set(i, d.get(i+s));
				d.set(28-s-1, 28, false);
			}
			BitSet ki = new BitSet(48);
			for (int j = 0; j < 48; j++) {
				int index = keySelection[j];
				if (index < 28)
					ki.set(j, c.get(index));
				else
					ki.set(j, d.get(index % 28));
			}
			keys[i] = ki;
			//			System.out.println("Key " + i + ": " + ki);
		}
	}

	public byte[] encryptBlock(byte[] block) {
		BitSet bs = BitSet.valueOf(block);
		bs = performInitialPermutation(bs);

		BitSet l = bs.get(0, 32);
		BitSet r = bs.get(32, 64);
		BitSet newL = (BitSet)l.clone();
		BitSet newR = (BitSet)r.clone();

		for (int i = 0; i < 16; i ++) {
			BitSet k = keys[i];
			newL = r;
			newR = l;
			newR.xor(function(r,k));
		}
		for (int i = 0; i < 64; i++) {
			if (i < 32)
				bs.set(i, newR.get(i));
			else
				bs.set(i, newL.get(i%32));
		}

		bs = performInverseInitialPermutation(bs);
		byte[] toReturn = new byte[8];
		Arrays.fill(toReturn, (byte)0);
		byte[] fill = bs.toByteArray();
		for (int i = 0; i < fill.length; i++)
			toReturn[i] = fill[i];
		return toReturn;

	}

	public byte[] decryptBlock(byte[] block) {
		BitSet bs = BitSet.valueOf(block);
		bs = performInitialPermutation(bs);

		BitSet l = bs.get(0, 32);
		BitSet r = bs.get(32, 64);
		BitSet newL = (BitSet)l.clone();
		BitSet newR = (BitSet)r.clone();

		for (int i = 15; i >= 0; i--) {
			BitSet k = keys[i];
			newL = r;
			newR = l;
			newR.xor(function(r,k));
		}
		for (int i = 0; i < 64; i++) {
			if (i < 32)
				bs.set(i, newR.get(i));
			else
				bs.set(i, newL.get(i%32));
		}

		bs = performInverseInitialPermutation(bs);
		byte[] toReturn = new byte[8];
		Arrays.fill(toReturn, (byte)0);
		byte[] fill = bs.toByteArray();
		for (int i = 0; i < fill.length; i++)
			toReturn[i] = fill[i];
		return toReturn;
	}

	private BitSet performInitialPermutation(BitSet bs) {
		BitSet toReturn = new BitSet(64);
		for (int i = 0; i < initialPermutation.length; i++)
			toReturn.set(i, bs.get(initialPermutation[i]));
		return toReturn;
	}

	private BitSet performInverseInitialPermutation(BitSet bs) {
		BitSet toReturn = new BitSet(64);
		for (int i = 0; i < initialPermutation.length; i++)
			toReturn.set(initialPermutation[i], bs.get(i));
		return toReturn;
	}

	private BitSet function(BitSet r, BitSet k) {
		BitSet eR = new BitSet(48);
		for (int i = 0; i < 48; i++) {
			eR.set(i, r.get(expansionFunction[i]));
		}
		eR.xor(k);
		BitSet[] b = new BitSet[8];
		for (int i = 0; i < 8; i++) {
			b[i] = new BitSet(6);
		}
		for (int i = 0; i < 48; i++) {
			b[i/6].set(i%6,eR.get(i));
		}
		BitSet[] c = new BitSet[8];
		for (int i = 0; i < 8; i++) {
			c[i] = new BitSet(4);
			int row = 0;
			row += b[i].get(0) ? 2 : 0;
			row += b[i].get(5) ? 1 : 0;
			int col = 0;
			for (int j = 1; j < 5; j++)
				col += b[i].get(j) ? (int)(Math.pow(2, 4 - j)): 0;
				byte temp = (byte)sBoxes[i][row][col];
				byte[] tempArr = new byte[1];
				tempArr[0] = temp;
				c[i] = BitSet.valueOf(tempArr);
		}
		BitSet cAll = new BitSet(32);
		for (int i = 0; i < 32; i++) {
			cAll.set(i, c[i/4].get(i%4));
		}
		BitSet toReturn = new BitSet(32);
		for (int i = 0; i < 32; i++) {
			int j = stringPermutation[i];
			toReturn.set(i, cAll.get(j));
		}
		return toReturn;
	}

	public String formatByte(byte b) {
		String bs = "00000000" + Integer.toBinaryString(b);
		return bs.substring(bs.length() - 8);
	}
}
