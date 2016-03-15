package des;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;

public class EncryptionDriver {

	public static void main(String[] args) throws Exception {
		boolean encrypt = !args[0].equals("--d");
		String keyString = args[1];
		byte[] key = keyString.getBytes();
		DES des = null;
		try {
			des = new DES(key);
		}
		catch (Exception e) {
			System.out.println("Error:" + e);
			System.exit(0);
		}

		String messageFileName = args[2];
		String resultFileName = args[3];
		try {
			Path messagePath = Paths.get(messageFileName);
			byte[] messageBytes = Files.readAllBytes(messagePath);
			
			FileOutputStream resultStream = new FileOutputStream(resultFileName);
			
			ArrayList<Byte> resultBytes = new ArrayList<Byte>();
			for (int i = 0; i < messageBytes.length; i += 8) {
				byte[] block;
				if (i + 8 <= messageBytes.length)
					block = Arrays.copyOfRange(messageBytes, i, i+8);
				else {
					block = new byte[8];
					Arrays.fill(block, (byte)0);
					for (int j = i; j < messageBytes.length; j++)
						block[j-i] = messageBytes[j];
				}
				byte[] resultBlock;
				if (encrypt)
					resultBlock = des.encryptBlock(block);
				else
					resultBlock = des.decryptBlock(block);
				for (int j = 0; j < resultBlock.length; j++) {
					resultBytes.add(new Byte(resultBlock[j]));
				}
				
			}
			
			try {
				byte[] result = new byte[messageBytes.length];
				for (int i = 0; i < messageBytes.length; i++)
				    result[i] = resultBytes.get(i).byteValue();
				resultStream.write(result);
			}
			finally {
				resultStream.close();
			}			
		}
		catch (Exception e) {
			throw e;
		}
	}
}
