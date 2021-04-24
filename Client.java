/*
=======================================
	Name - Hay Munn Hnin Wai 
   UOW ID - 6573277 
   Assignment - 1, Network Security 
======================================
 */
//package assn1;

import bwmorg.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import java.util.Random;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Client {
    
    static BigInteger exponent_b;   //Random generated exponent b
    static BigInteger shareKey;
    static int nb;

    //SHA-1 Hash Algorithm for Password 
    public static String HashedFunction(String input) 
    { 
        try { 
            // getInstance() method is called with algorithm SHA-1 
            MessageDigest md = MessageDigest.getInstance("SHA-1"); 
  
            // digest() method is called 
            // to calculate message digest of the input string 
            // returned as array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
  
            // Add preceding 0s to make it 32 bit 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
            // return the HashText 
            return hashtext; 
            } 
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
    //RC4 Encryption & Decryption goes here .............
    static String decodeBase64(String encodedData){
        byte[] b = Base64.getDecoder().decode(encodedData);
        String decodedData = DatatypeConverter.printHexBinary(b);
        return decodedData;
    }

    static String encodeBase64(byte[] data){
        byte[] b = Base64.getEncoder().encode(data);
        String encodedData = new String(b);
        /*String encodedData = DatatypeConverter.printHexBinary(b);*/
        return encodedData;
    }
    private static byte[] encrypt(String plaintext, SecretKey secretKey, Cipher rc4) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        rc4.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertextBytes = rc4.doFinal(plaintextBytes);
        
        String encodedString = Base64.getEncoder().withoutPadding().encodeToString(ciphertextBytes);
        //System.out.println("RC4 ciphertext base64 encoded: " + encodedString);
	//System.out.println("encodedBytes : " + new String(ciphertextBytes));
        return ciphertextBytes;
    }
    private static String decrypt(SecretKey secretKey, Cipher rc4, byte[] ciphertextBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
       
        try{
            rc4.init(Cipher.DECRYPT_MODE, secretKey, rc4.getParameters());  
            byte[] byteDecryptedText = rc4.doFinal(ciphertextBytes);
            String plaintextBack = new String(byteDecryptedText);
            System.out.println("Decrypted back to: " + plaintextBack);
            return plaintextBack;            //Return in String format 
            }
            catch(Exception e)
            {
                System.out.println("Error while Decrypting: " + e.toString());
            }
        return null;
    }
    private static BigInteger Calculate_modPow(Long pp, Long gg)
     {
        BigInteger p = BigInteger.valueOf(pp);
        BigInteger g = BigInteger.valueOf(gg);
        
        Random randomGenerator = new Random();
       int no = randomGenerator.nextInt(100)+15;  //Get random No "a"
        exponent_b = BigInteger.valueOf(no);    //Convert to BigInt 
        BigInteger result = g.modPow(exponent_b, p); 
        
        String expression = g + "^" + exponent_b + " % "
                            + p + " = " + result; 
        return result ;
    }
    private static BigInteger getExponent()        
    { 
        return exponent_b;  
    }
    private static String Key2(Long p, Long g) throws IOException  //get g^b Modp
    {
        String  pp = String.valueOf(p);
        String gg = String.valueOf(g);
        String result = String.valueOf(Calculate_modPow(p, g));  //get g^b ModP
        String str =  g + "^" + getExponent() + " % " + p;
        
        return result;
    }
    private static String getNB(int nonceA) {
        Random rand = new Random();
        nb = rand.nextInt(500)+20;    //Generate NB 
        String NB = String.valueOf(nb);  
        String str = nonceA + "," +  NB;   //NA+1, NB   
        return str; 
    }    
    private static boolean CheckCorrectNB(int nBPlus)  //NB+1 From Host
    {
        boolean found = false;
        try
        {
            int a = nb + 1;      // get nB from above & +1
            int b = nBPlus;     //nB+1 to check     
            if ( a == b )
            {
                found = true;
            }
            else if ( a!= b)
            {
                found = false;
            }
        }
        catch(NumberFormatException e)
        {
            System.out.println("Error: "+ e.toString()); 
        }
        return found;
    }
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException 
    {
        System.out.println("----------------Detail of Client-------------------");
        System.out.println("Username: Bob,Correct Password to Run: \"123456\" ");
        System.out.println("-------------------Detail of Client End-------------------------");
        
        BufferedReader user_input  = new BufferedReader(new InputStreamReader(System.in));
        //Sending out 
        DatagramSocket client_socket = new DatagramSocket();
        InetAddress ip =InetAddress.getByName("localhost");
        byte out_data [] = new byte[2048];
        
        //Receiving 
        byte in_data [] = new byte[2048];
        
        //Sending out User Name
        System.out.print("Enter Username: ");
        String username = user_input.readLine().toUpperCase();
        out_data = username.getBytes();   //transfer to byte form 
        DatagramPacket namePacket = new DatagramPacket(out_data, out_data.length, ip,1234 );
        client_socket.send(namePacket);
        
        //Prompt client to enter password 
        System.out.print("Enter password: ");
        String password = user_input.readLine();
        HashedFunction(password);
        
        System.out.println("");
        //Receiving in from host -->E(H(pw),p,g,g^a modp)
        DatagramPacket serverPacket = new DatagramPacket(in_data, in_data.length);
        client_socket.receive(serverPacket);
        String EncryptedMessage = new String(serverPacket.getData(),0, serverPacket.getLength());
        System.out.print("RECEIVE E(H(pw),p,g,g^a Modp) FROM HOST :" + EncryptedMessage);
        System.out.println("");
        
        //Decrypting Message --> E(H(pw),p,g,g^a modp) .....
        String hashedKey = HashedFunction(password);  //get H(pw) from user's Input
        Key key = new SecretKeySpec(Hex.decode(hashedKey), "RC4"); //String to key conversion using Hex.decode to convert to byte []
        //Convert to Bytes
        byte [] EncryptedBytes = Base64.getDecoder().decode(EncryptedMessage.getBytes());

        // Create Cipher instance and initialize it to Decryption mode
        Cipher rc4 = Cipher.getInstance("RC4");  // Transformation of the algorithm
        rc4.init(Cipher.DECRYPT_MODE, key);
        String Decrypted_Message = decrypt((SecretKey) key, rc4, EncryptedBytes);
        System.out.println("");
        
        try{
            //Readline --> Decrypted Message  
            String line = Decrypted_Message;
            String[] values = line.trim().split("[\\W]+");  //Split Non-word chars 
            Long p= 0L;
            Long g= 0L;
            Long answer = 0L;
            for ( int i = 0; i < values.length; i++)
            {
               p = Long.valueOf(values[0]);
               g = Long.valueOf(values[1]);
               answer =  Long.valueOf(values[2]);       //get g^a ModP  
            }
            BigInteger pp, gg, Ans;     
            pp = BigInteger.valueOf(p);
            gg = BigInteger.valueOf(g);
            Ans = BigInteger.valueOf(answer);
 
            //Sending Encrypted to Host --> E(H(pw), g^b Modp)
            String plaintext =  Key2(p, g);                 //get g^b modp
            byte[] plainBytes = plaintext.getBytes();

            // Create Cipher instance and initialize it to encrytion mode
            rc4.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherBytes = rc4.doFinal(plainBytes);
            String encoded = encodeBase64(cipherBytes);
            //String decoded = decodeBase64(encoded);
            //byte[] ciphertextBytes = encrypt(plaintext, (SecretKey) key, rc4);

            InetAddress IP_add1 = serverPacket.getAddress();
            int port = serverPacket.getPort();
            String E2 = Base64.getEncoder().encodeToString(encrypt(plaintext, (SecretKey) key, rc4));
            out_data = E2.getBytes();
            DatagramPacket Key2 = new DatagramPacket(out_data,out_data.length,IP_add1,port);
            System.out.println("SENDING E(H(pw),g^b Modp)TO HOST ............"+ "\n");
            client_socket.send(Key2);
          
            //Compute Share Key here 
            System.out.println("P : "+ pp);
            System.out.println("g : "+ gg);
            System.out.println("Ans: "+ Ans);
                
            shareKey= Ans.modPow(exponent_b, pp);
            System.out.println("SHARE KEY(Client)in Digit :" + shareKey);
            String sKey = String.valueOf(shareKey);  //Convert skey to String 
            System.out.println("SHARE KEY(Client) is Computed: "+ HashedFunction(sKey));
            System.out.println("");
            
            //Receiveing Encrypted --> E(K,NA) 
            client_socket.receive(serverPacket);
            String EncryptedNonceA = new String(serverPacket.getData(),0,serverPacket.getLength());
            System.out.println("RECEIVED ENCRYPTED E(K,NA): " + EncryptedNonceA);
           
            //Decrypting Nonce A from Host 
            String hashedKey2 = HashedFunction(sKey);  //get H(pw) from user's Input
            Key K2 = new SecretKeySpec(Hex.decode(hashedKey2), "RC4"); 
             //Convert to Bytes
            byte [] EncryptedBytes2 = Base64.getDecoder().decode(EncryptedNonceA.getBytes());
            rc4.init(Cipher.DECRYPT_MODE, K2);   //Encrypt with ShareKey K 
            String Decrypted_Message2 = decrypt((SecretKey) K2, rc4, EncryptedBytes2);  //Using K2 to Decrypt
            System.out.println("");
            int Nonce_A = Integer.valueOf(Decrypted_Message2);  //NA 
            int Nonce_APlus = Nonce_A +1;                       //NA+1 
            
            //Encrypted Message --> E(K,NA+1, NB)
            String plaintext2 = String.valueOf(getNB(Nonce_APlus));   //NA+1 
                System.out.println("[NOT SEND]- NA+1,NB for Server to check: "+ plaintext2);
            //byte[] plainBytes2 = plaintext2.getBytes();
            rc4.init(Cipher.ENCRYPT_MODE, K2);      //Encrypt with ShareKey K 
            
            //Sending out Encrypted NA --->E(K,NA+1,NB) 
            String E3 = Base64.getEncoder().encodeToString(encrypt(plaintext2, (SecretKey) K2, rc4));
            out_data = E3.getBytes();
            DatagramPacket step5 = new DatagramPacket(out_data,out_data.length,ip,port);
            System.out.println("SENDING ENCRYPTED E(K,NA+1,NB) TO HOST .............");
            client_socket.send(step5);
            
            //Receive Encrypted--->E(K,NB+1)
            System.out.println("");
            client_socket.receive(serverPacket);
            String Encrypted_NBPlus = new String(serverPacket.getData(),0,serverPacket.getLength());
            System.out.println("RECEIVED ENCRYPTED E(K,NB+1): " + Encrypted_NBPlus);    //nB+1
               
            //Decrypting -->E(K,NB+1) 
             //Convert to Bytes
            byte [] EncryptedBytes3 = Base64.getDecoder().decode(Encrypted_NBPlus.getBytes());
            rc4.init(Cipher.DECRYPT_MODE, K2);   //Encrypt with ShareKey K 
            String Decrypted_Message3 = decrypt((SecretKey) K2, rc4, EncryptedBytes3);  //Using K2 to Decrypt
            System.out.println("");
            int Nonce_BPlus = Integer.valueOf(Decrypted_Message3);  //Convert NB+1 to int 
            boolean checkHost = CheckCorrectNB(Nonce_BPlus);   
            
            //Authentication Host 
            if (checkHost == true )
            {
                System.out.println("HandShake is successful with Host....");
                Scanner sc = new Scanner(System.in);
                while(true)
                {
                    //Start Conversation with Host
                    System.out.print("\nClient Message in PLAINTEXT: ");
                    String clientMessage = sc.nextLine();
                    out_data = clientMessage.getBytes();
                    DatagramPacket sendpacket = new DatagramPacket(out_data,out_data.length,ip,1234);
                    
                    //Client Exit 
                    if(clientMessage.equalsIgnoreCase("exit"))
                    {  
			System.out.println("CONNECTION ENDED BY CLIENT");
			System.exit(0);
                    }
                    //Integerity Check Value(Hash) for Client Message 
                      //THIS IS WHERE THE CLIENT --->H(K||M||K)
                    String K_M_K = K2 + clientMessage + K2;             //Use Client's ShareKey K2
                    String Integrity_check = HashedFunction(K_M_K);    //Hash(K||M||K)
                    System.out.println("NOT SEND - [CLIENT H(K||M||K)] for server to check:" + Integrity_check);
                    
                    //Now Comupte C = E(K,M||Hash)
                    String C = clientMessage + "||" + Integrity_check;  //M||Hash 
                    //Encrypted --->E(K,M||Hash) 
                    rc4.init(Cipher.ENCRYPT_MODE, K2);      //Encrypt with ShareKey K 
                    String Encrypted_M_H = Base64.getEncoder().encodeToString(encrypt(C,(SecretKey) K2, rc4));
                    System.out.println("Sending Encrypted E(K,M||Hash): "+ Encrypted_M_H);         
                    
                    //Sending out Encrypted E(K,M||Hash)
                    out_data = Encrypted_M_H.getBytes();
                    DatagramPacket send_c = new DatagramPacket(out_data,out_data.length,ip,1234);
                    client_socket.send(send_c);
                        
                   //Receiving Message from Server 
                    DatagramPacket receivePacket = new DatagramPacket(in_data,in_data.length);
                    client_socket.receive(receivePacket);
                    String Encrypted_mh = new String(receivePacket.getData(),0,receivePacket.getLength());
                    System.out.println("\nClient(receiving): " + Encrypted_mh);
                    
                    //Integrity Check (H) of Server Message
                    //Decrypting--->(K,M||Hash) ----> Client's Message||Hash
                    byte [] Encrypted_MH = Base64.getDecoder().decode(Encrypted_mh.getBytes());
                    rc4.init(Cipher.DECRYPT_MODE, K2);   //Encrypt with ShareKey K 
                    String RC4_Decrypted_MH = decrypt((SecretKey) K2, rc4, Encrypted_MH);
                    String decrypted_MH= RC4_Decrypted_MH.substring(0, RC4_Decrypted_MH.indexOf("||"));
                    String decrypted_server_m = decrypted_MH.substring(decrypted_MH.lastIndexOf("||") + 1);
                    String decrypted_server_h = RC4_Decrypted_MH.substring(RC4_Decrypted_MH.lastIndexOf("||") + 2);

                    System.out.println("Decrypted client Message: " + decrypted_server_m);
                    System.out.println("Decrypted client Hash H : " + decrypted_server_h);
                    System.out.println();

                    //Integrity Check (H)= H(K||M||K) from Server
                    String K_M_K2 = K2 + decrypted_server_m + K2;      //Using Server Share Key
                    String Decrypted_Client_hash = HashedFunction(K_M_K2);            //Hash(K||M||K)
                    System.out.println("NOT SEND - [Client H(K||M||K)] to check:" + Decrypted_Client_hash);

                    String client_h = new String(Decrypted_Client_hash);  
                    String server_h = new String(decrypted_server_h);     

                    if (client_h.equals(server_h))
                    {
                        System.out.println("Result: Client H = Server H");
                        System.out.println("Decryption is Successful");
                    } 
                    else
                    {
                        System.out.println("Result: Client H DIFFERENT as server H");
                        System.out.println("Communication error");
                        System.out.println("Rejected!");
		}
                
                }
            }
            else if (checkHost == false)
            {
                System.out.println("Authetication Failed!");
                String fail = "Client: Authentication Failed";
                //System.out.println(fail + "Failed !");
                out_data = fail.getBytes();
                DatagramPacket fail_message = new DatagramPacket(out_data,out_data.length,ip,port);
                client_socket.send(fail_message);
                System.exit(0);             //Client terminate the connection
                client_socket.close(); 
            }
        }
        catch(Exception e){
            System.out.println("Error!");
            System.out.println("Decryption Failed ! "+ e.toString()); 
        }
    }      
}



