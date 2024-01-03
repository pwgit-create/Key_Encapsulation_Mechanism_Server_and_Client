import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String... args) throws ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException {

        KemSenderClient kemSenderClient = new KemSenderClient();

        kemSenderClient.Start();
    }

}
