import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class KemSenderClient {


    protected void Start () throws ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException {

        //1. Get public key from KemReceiver

        PublicKey publicKey = null;

        try(Socket socket = new Socket("LOCALHOST",7500)){
            ObjectInputStream objectInputStream =  new ObjectInputStream(socket.getInputStream());



            if(socket.isConnected()) {

                try{publicKey =(PublicKey) objectInputStream.readObject();}
                catch (EOFException eofException){     System.out.println("End of file");}


                }


        assert publicKey != null;
        System.out.println(publicKey.getAlgorithm());


        // Step 2 , Calculate the Shared Symmetric Key at the senders side

        KEM.Encapsulated kemEncapsulated = CreateKemEncapsulated(publicKey);
        SecretKey sharedSecretKeySender = kemEncapsulated.key();
        System.out.println(sharedSecretKeySender.hashCode());

        //Step3. Send Encapsulated KEM to Receiver

        if(socket.isConnected()){
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.write(kemEncapsulated.encapsulation());
            dataOutputStream.flush();
        }
        }
        catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    private KEM.Encapsulated  CreateKemEncapsulated(PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException {

        //sender side
        KEM kem1 = KEM.getInstance("DHKEM");
        KEM.Encapsulator sender = kem1.newEncapsulator(publicKey);
        return  sender.encapsulate();

    }

}