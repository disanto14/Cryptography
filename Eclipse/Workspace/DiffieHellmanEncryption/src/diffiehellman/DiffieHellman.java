package diffiehellman;

import java.math.BigInteger;

public class DiffieHellman {
	
	private BigInteger p;
	private BigInteger g;
	private BigInteger key;
	private BigInteger inverseKey;
	
	public DiffieHellman(BigInteger p, BigInteger g, BigInteger a, BigInteger gb) {
		this.p = p;
		System.out.println("P: " + this.p);
		this.g = g;
		System.out.println("G: " + this.g);
		this.key = gb.modPow(a, this.p);
		System.out.println("Key: " + this.key);
		BigInteger pMinus2 = this.p.subtract(new BigInteger("2"));
		System.out.println("P-2: " + pMinus2);
		this.inverseKey = this.key.modPow(pMinus2, this.p);
		System.out.println("Inverse Key: " + this.inverseKey);
	}
	
	/**
	 * ElGamal encryption algorithm
	 * @param input - the plaintext message
	 * @return output - the cryptotext message
	 */
	public byte[] encrypt(byte[] input) {
		System.out.println("M length: " + input.length);
		BigInteger m = new BigInteger(input);
		System.out.println("M: " + m.toString());
		BigInteger c = m.multiply(key).mod(p);
		System.out.println("C: " + c.toString());
		byte[] output = c.toByteArray();
		System.out.println("C length: " + output.length);
		return output;
	}
	
	/**
	 * ElGamal decryption algorithm
	 * @param input - the cryptotext message
	 * @return output - the plaintext message
	 */
	public byte[] decrypt(byte[] input) {
		System.out.println("C length: " + input.length);
		BigInteger c = new BigInteger(input);
		System.out.println("C: " + c.toString());
		BigInteger m = c.multiply(inverseKey).mod(p);
		System.out.println("M: " + m.toString());
		byte[] output = m.toByteArray();
		System.out.println("M length: " + output.length);
		return output;
	}
	
}
