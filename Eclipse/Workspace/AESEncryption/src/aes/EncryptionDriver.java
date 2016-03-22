package aes;

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
		AES aes = null;
		aes = new AES(key);
		

		String messageFileName = args[2];
		String resultFileName = args[3];
		try {
			Path messagePath = Paths.get(messageFileName);
			byte[] messageBytes = Files.readAllBytes(messagePath);
			
			FileOutputStream resultStream = new FileOutputStream(resultFileName);
			
			ArrayList<Byte> resultBytes = new ArrayList<Byte>();
			for (int i = 0; i < messageBytes.length; i += 16) {
				byte[] block;
				if (i + 16 <= messageBytes.length)
					block = Arrays.copyOfRange(messageBytes, i, i+16);
				else {
					block = new byte[16];
					Arrays.fill(block, (byte)0);
					for (int j = i; j < messageBytes.length; j++)
						block[j-i] = messageBytes[j];
				}
				byte[] resultBlock;
				if (encrypt)
					resultBlock = aes.encrypt(block);
				else
					resultBlock = aes.decrypt(block);
				for (int j = 0; j < resultBlock.length; j++) {
					resultBytes.add(new Byte(resultBlock[j]));
				}
				
			}
			
			try {
				int length = messageBytes.length % 16 == 0? messageBytes.length : (messageBytes.length / 16 + 1) * 16;
				byte[] result = new byte[length];
				for (int i = 0; i < length; i++)
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
