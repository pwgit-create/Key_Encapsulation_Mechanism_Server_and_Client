
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class KemReceiverServer {


    private final static int PORT = 7500;

    private KeyPair kp = null;

    public KemReceiverServer() throws NoSuchAlgorithmException {

        kp = KeyUtil.GenerateKeyPair();
    }

    public void Start() {

        ExecutorService pool = Executors.newFixedThreadPool(500);
        while (true) {
            try (ServerSocket server = new ServerSocket(PORT);) {
                Socket connection = server.accept();

                pool.execute(new KempReceiverServerTask(connection));

            } catch (IOException ioException) {
                System.err.println(ioException);
            }
        }


    }

    private class KempReceiverServerTask implements Runnable {

        private Socket connection;

        private KempReceiverServerTask(Socket connection) {
            this.connection = connection;

        }

        @Override
        public void run() {

            try {

                System.out.println(kp.getPublic().getAlgorithm());
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(connection.getOutputStream());

                // 1. Send public key to receiver
                objectOutputStream.writeObject(kp.getPublic());
                objectOutputStream.flush();


                //2. Receive KEM encapsulated bytes from sender

                byte[] kemBytes = connection.getInputStream().readAllBytes();


                //3. Calculate the Shared Symmetric Key at the receivers side

                SecretKey sharedSecretReceiver = CalculateSharedSecret(kp.getPrivate(), kemBytes);

                System.out.println("Shared Secret Receiver -> " + sharedSecretReceiver.hashCode());

            } catch (IOException ioException) {
                System.err.println(ioException);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }

        }

        private SecretKey CalculateSharedSecret(PrivateKey privateKey, byte[] kemEncapsulatedBytes) throws NoSuchAlgorithmException, InvalidKeyException {

            KEM kem2 = KEM.getInstance("DHKEM");

            KEM.Decapsulator receiver = kem2.newDecapsulator(privateKey);


            try {
                return receiver.decapsulate(kemEncapsulatedBytes);
            } catch (DecapsulateException e) {
                System.err.println(e.getMessage());
            }
            return null;
        }
    }

}