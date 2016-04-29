package ellipticcurve;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

public class ECC {

	class Point {
		BigInteger x, y;
		public Point() {
			x = null;
			y = null;
		}
		public Point(BigInteger a, BigInteger b) {
			x = a.mod(ECC.this.n);
			y = b.mod(ECC.this.n);
		}
		
		public boolean equals(Point a) {
			return x.equals(a.x) && y.equals(a.y);
		}
		public String toString() {
			return "(" + x + ", " + y + ")";
		}
	}

	private final Point infinity = new Point() {	
		public boolean equals(Point a) { return this == a; }
	};

	private EllipticCurve curve;
	private BigInteger n;
	private Point g;
	private Point key;
	private Point inverseKey;
	private int encryptBlockSize, decryptBlockSize;
	private boolean useLazyMapping;
	private BigInteger k;

	public ECC(BigInteger a, BigInteger b, BigInteger n, BigInteger nA, BigInteger nB) {
		this.n = n;
		useLazyMapping = !n.mod(new BigInteger("4")).equals(new BigInteger("3"));
		k = new BigInteger("1000");
		decryptBlockSize = n.toByteArray().length;
		encryptBlockSize = 0;
		BigInteger m = new BigInteger("256");
		BigInteger limit = new BigInteger("1");
		while (limit.multiply(k).compareTo(n) < 1) {
			limit = limit.multiply(m);
			encryptBlockSize++;
		}
		encryptBlockSize--;
		this.curve = new EllipticCurve(new ECFieldFp(n), a, b);
		for (long i = 0; i < n.longValue(); i++) {
			BigInteger x = new BigInteger(new Long(i).toString());
			BigInteger ySquared = x.modPow(new BigInteger("3"), n).add(x.multiply(curve.getA())).add(curve.getB()).mod(n);
			BigInteger y = ySquared.modPow(n.add(new BigInteger("1")).divide(new BigInteger("4")), n);
			if (y.modPow(new BigInteger("2"), n).equals(ySquared)) {
				this.g = new Point(x, y);
				break;
			}
		}
		key = multiply(multiply(g, nA), nB);
		inverseKey = new Point(key.x, key.y.negate());
		System.out.println("N: " + n);
		System.out.println("Curve: y^2 = x^3 + " + curve.getA() + "x + " + curve.getB());
		System.out.println("Block Size: " + encryptBlockSize);
		System.out.println("Using Koblitz: " + !useLazyMapping);
		System.out.println("K: " + k);
		System.out.println("G: " + g);
		System.out.println("Key: " + key);
		System.out.println("Inverse Key: " + inverseKey);
		System.out.println("Key confirm: " + multiply(g, nA.multiply(nB)));
	}
	
	public int encryptBlockSize() {
		return encryptBlockSize;
	}
	
	public int decryptBlockSize() {
		return decryptBlockSize;
	}
	
	public byte[] encrypt(byte[] input) {
		Point m = mapToPoint(input);
		if (useLazyMapping || m == null) {
			m = mapToPointLazy(input);
		}
		Point c = add(m, key);
		System.out.println("Encrypted " + m + " to " + c);
		byte[] output = new byte[encryptBlockSize];
		if (useLazyMapping) {
			output = mapFromPointLazy(c);
		}
		else {
			output = mapFromPointEncrypt(c);
		}
		return output;
	}
	
	public byte[] decrypt(byte[] input) {
		Point c = mapToPointDecrypt(input);
		if (useLazyMapping || c == null) {
			c = mapToPointLazy(input);
		}
		Point m = add(c, inverseKey);
		System.out.println("Decrypted " + c + " to " + m);
		byte[] output = new byte[encryptBlockSize];
		if (useLazyMapping) {
			output = mapFromPointLazy(m);
		}
		else {
			output = mapFromPoint(m);
		}
		return output;
	}
	
	public Point mapToPoint(byte[] input) {
		BigInteger m = new BigInteger(input);
		for (int j = 0; j < k.intValue(); j++) {
			BigInteger x = m.multiply(k).add(new BigInteger(new Integer(j).toString()));
			BigInteger ySquared = x.modPow(new BigInteger("3"), n).add(x.multiply(curve.getA())).add(curve.getB()).mod(n);
			BigInteger y = ySquared.modPow(n.add(new BigInteger("1")).divide(new BigInteger("4")), n);
			if (y.modPow(new BigInteger("2"), n).equals(ySquared)) {
				return new Point(x, y);
			}
		}
		return null;
	}
	
	public Point mapToPointDecrypt(byte[] input) {
		BigInteger m = new BigInteger(input);
		for (int j = 0; j < k.intValue(); j++) {
			BigInteger x = m.add(new BigInteger(new Integer(j).toString()));
			BigInteger ySquared = x.modPow(new BigInteger("3"), n).add(x.multiply(curve.getA())).add(curve.getB()).mod(n);
			BigInteger y = ySquared.modPow(n.add(new BigInteger("1")).divide(new BigInteger("4")), n);
			if (y.modPow(new BigInteger("2"), n).equals(ySquared)) {
				return new Point(x, y);
			}
		}
		return null;
	}
	
	public byte[] mapFromPoint(Point p) {
		return p.x.divide(k).toByteArray();
	}
	
	public byte[] mapFromPointEncrypt(Point p) {
		return p.x.toByteArray();
	}

	public Point mapToPointLazy(byte[] input) {
		if (input.length != encryptBlockSize) {
			return null;
		}
		byte[] xBytes = new byte[encryptBlockSize / 2];
		byte[] yBytes = new byte[encryptBlockSize / 2];
		for (int i = 0; i < encryptBlockSize; i++) {
			if (i < encryptBlockSize / 2) {
				xBytes[i] = input[i];
			}
			else {
				yBytes[i - (encryptBlockSize / 2)] = input[i];
			}
		}
		BigInteger x = new BigInteger(xBytes);
		BigInteger y = new BigInteger(yBytes);
		return new Point(x,y);
	}

	public byte[] mapFromPointLazy(Point p) {
		byte[] output = new byte[encryptBlockSize];
		byte[] xBytes = p.x.toByteArray();
		byte[] yBytes = p.y.toByteArray();
		for (int i = 0; i < xBytes.length; i++) {
			output[i + (encryptBlockSize / 2) - xBytes.length] = xBytes[i];
		}
		for (int i = 0; i < yBytes.length; i++) {
			output[i + encryptBlockSize - yBytes.length] = yBytes[i];
		}
		return output;
	}
	
	public Point multiply(Point a, BigInteger d) {
		Point q = infinity;
		Point p = a;
		byte[] bytes = d.toByteArray();
		for (int i = bytes.length - 1; i >= 0; i--) {
			for (int j = 0; j < 8; j++) {
				if (isNthBitSet(bytes[i], j)) {
//					System.out.println("i: " + i + ", j: " + j);
					q = add(p, q);
				}
				p = add(p, p);
			}
		}
		return q;
	}
	
	private boolean isNthBitSet (byte c, int n) {
	    byte[] mask = {(byte) 128, 64, 32, 16, 8, 4, 2, 1};
	    return ((c & mask[7-n]) != 0);
	}

	public Point add(Point p, Point q) {
		if (p == infinity) {
//			System.out.println("P is infinity");
			return q;
		}
		if (q == infinity) {
//			System.out.println("Q is infinity");
			return p;
		}
		BigInteger mNum = new BigInteger("0");
		BigInteger mDenom = new BigInteger("0");
		BigInteger m = new BigInteger("0");
		if (p.equals(q)) {
//			System.out.println("P == Q");
			mNum = mNum.add(p.x);
			mNum = mNum.modPow(new BigInteger("2"), n);
			mNum = mNum.multiply(new BigInteger("3"));
			mNum = mNum.add(curve.getA());
			mNum = mNum.mod(n);
			mDenom = mDenom.add(p.y);
			mDenom = mDenom.multiply(new BigInteger("2"));
			mDenom = mDenom.mod(n);
		}
		else {
//			System.out.println("P != Q");
			mNum = new BigInteger(q.y.toByteArray());
			mNum = mNum.subtract(p.y);
			mNum = mNum.mod(n);
			mDenom = new BigInteger(q.x.toByteArray());
			mDenom = mDenom.subtract(p.x);
			mDenom = mDenom.mod(n);
		}
		if (mDenom.equals(new BigInteger("0"))) {
//			System.out.println("M is infinity");
//			System.out.println("M denom: " + mDenom.toString());
			return infinity;
		}
		else {
//			System.out.println("MNum: " + mNum.toString());
//			System.out.println("MDenom: " + mDenom.toString());
			m = mNum.multiply(mDenom.modInverse(n));
			m = m.mod(n);
//			System.out.println("M: " + m.toString());
		}
		BigInteger x3 = new BigInteger(m.toByteArray());
		x3 = x3.modPow(new BigInteger("2"), n);
		x3 = x3.subtract(p.x);
		x3 = x3.subtract(q.x);
		x3 = x3.mod(n);
		BigInteger y3 = new BigInteger(p.x.toByteArray());
		y3 = y3.subtract(x3);
		y3 = y3.multiply(m);
		y3 = y3.subtract(p.y);
		y3 = y3.mod(n);
		return new Point(x3, y3);
	}
}
