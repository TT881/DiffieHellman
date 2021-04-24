/*
=======================================
	Name - Hay Munn Hnin Wai 
   UOW ID - 6573277 
   Assignment - 1, Network Security 
======================================
 */
 
//package assn1;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.SecretKey;

import bwmorg.bouncycastle.util.encoders.Hex;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Host { 
    static String encodedString;
    static BigInteger exponent_a;
    static BigInteger shareKey;
    static String na;
    static int PlusNa;
    
    private static long primeGenerator()
    {
      BigInteger bi;

      int bitLength = 32;
      Random rnd = new Random();

      bi = BigInteger.probablePrime(bitLength, rnd);
      Long bi1 =  bi.longValue();  //Convert to Long 
      
     if (!isPrime(bi1))    //Test Prime no
     {
         return 0;
     }
     return bi1;
   }
    //Check isPrime()
    private static boolean isPrime(long n)
    {
        for (int i = 2; i <= Math.sqrt(n); i++) {
            if (n % i == 0) {
                return false;
            }
        }
        return true;
    }
    private static pgGenerator primitiveElement() throws IOException
    {
      long pValue = primeGenerator();     //Get p from primeGenerator()
      Random randomGenerator = new Random();
      long gValue = randomGenerator.nextInt(10000);
      
      while(gValue> pValue)
    {
        long gValue2=randomGenerator.nextInt(10000);
        //g must < p and g is a Primitive root of p!
        if(gValue2<pValue)
        {
            gValue = gValue2;
            break;
        }
    }
    long getDivisor = (pValue-1)/2;
    BigInteger bi1,bi2,bi3,bi4;
    
    bi1= BigInteger.valueOf(getDivisor);
    bi2 = BigInteger.valueOf(pValue);
    bi3 = BigInteger.valueOf(gValue);
    bi4= bi3.modPow(bi1,bi2);       //Calculate primitive element
    long calculatedValue = bi4.longValue();
    
    //If gValue = 1 , calculate again with loop
    while(calculatedValue == 1)  
    {
        long gValue3 =randomGenerator.nextInt(10000);
        long getDivisorInLoop = (pValue-1)/2;
        BigInteger bi5,bi6,bi7,bi8;

        bi5=BigInteger.valueOf(getDivisorInLoop);
        bi6 = BigInteger.valueOf(pValue);
        bi7 = BigInteger.valueOf(gValue3);
        bi8= bi7.modPow(bi5,bi6);           //Calculate primitive element 

        long calculatedValueInLoop = bi8.longValue();
        //System.out.println(calculatedValueInLoop);
        if(calculatedValueInLoop!=1)
        {
            gValue=gValue3;
            break;
        }
    }
       BigInteger generatorValue,primeValue;
       generatorValue = BigInteger.valueOf(gValue);
       primeValue = BigInteger.valueOf(pValue);

       //Convert to Long
       Long primeNo =  primeValue.longValue();
       Long gVal =  generatorValue.longValue();
       return new pgGenerator(primeNo,gVal);  
    } 
    private BigInteger Calculate_modPow(Long pp, Long gg)
     {
        BigInteger p = BigInteger.valueOf(pp);
        BigInteger g = BigInteger.valueOf(gg);
        
        Random randomGenerator = new Random();
        int no = randomGenerator.nextInt(100)+15;  //Get random No "a"
        exponent_a = BigInteger.valueOf(no);    //Convert to BigInt 
        BigInteger result = g.modPow(exponent_a, p); 
        
        String expression = g + "^" + exponent_a + " % "
                            + p + " = " + result;
        // Perform modPow operation on the objects and exponent 
        
        return result ;
    }
    private static BigInteger getExponent() {
        return exponent_a;  
    }
    private String Key1(Long p, Long g) throws IOException
    {
        String  pp = String.valueOf(p);
        String gg = String.valueOf(g);
        String result = p + "," + g + "," + Calculate_modPow(p, g);
        String str = g + "," + p + "," + g + "^" + exponent_a + " % " + p;
        
        // System.out.println(str);
        return result; 
    }
    private static int getRandomNA() {
        Random rand = new Random();
        int NA = rand.nextInt(200)+15;  //Get NA 
        return NA;
    }
    private static String getNonce(BigInteger NA) 
    {
       na = String.valueOf(NA); 
       getNoncePlus(na);    //Pass to NAPlus
       return na;
    }
    private static int getNoncePlus(String a)    //Calculate NA+1 
    {
       PlusNa = Integer.valueOf(a);
       return PlusNa;
    }
    private static boolean CheckCorrectNonceA(int nAPlus)  //Na+1 From Client
    {
        boolean found = false;
        try
        {
            int a = Integer.valueOf(na);
            int b = PlusNa;
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
            System.out.println("Error!"); 
        }
        return found;
    }
//SHA-1 Hash Algorithm for Password 
    public static String HashedPassword(String input) 
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
    private static void ReadTxtFile(String input)throws Exception
    {
        Scanner sc = new Scanner (new File("Alice.txt"));
        String line;
        
        while(sc.hasNextLine())
        {
            line = sc.nextLine();
            String[] info = line.split(",");
            String p = String.valueOf(info[0]);
            String g = String.valueOf(info[1]);
            String Hpw = String.valueOf(info[2]);        
            System.out.println("\"p , g , Hashed Password\" : "+ p +" ,"+ g + " ," + Hpw);    
        }
        sc.close();         
    }
    //---------RC4 Encryption & Decryption goes here----------
     static String decodeBase64(String encodedData){
        byte[] b = Base64.getDecoder().decode(encodedData);
        String decodedData = DatatypeConverter.printHexBinary(b);
        return decodedData;
    }
    static String encodeBase64(byte[] data){
        byte[] b = Base64.getEncoder().encode(data);
        String encodedData = new String(b);
        //String encodedData = DatatypeConverter.printHexBinary(b);*/
        return encodedData;
    }
    private static byte[] encrypt(String plaintext, SecretKey secretKey, Cipher rc4) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        rc4.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertextBytes = rc4.doFinal(plaintextBytes);
        encodedString = Base64.getEncoder().withoutPadding().encodeToString(ciphertextBytes);
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
    public static void main ( String [] args ) throws SocketException, UnknownHostException, IOException, Exception{
       
        pgGenerator pg = primitiveElement() ;
        Host h = new Host();
        h.Calculate_modPow(pg.getP(), pg.getG());
        
        //pgGenerator a = new pgGenerator();
        System.out.println("-------------Detail of Server-------------");
        pg.WritetoFile("Alice.txt");
        System.out.println("Successfuly Created \"Alice.txt\" file! \n");
        System.out.println("Reading Content from \"Alice.txt\" file");
        //ReadTxtFile("Alice.txt");  
        
        System.out.println("-------------------------------------------");
        //Receiving 
        DatagramSocket serverSocket = new DatagramSocket(1234);
        byte in_data[] = new byte[2048];
        //Sending out
        BufferedReader server_input =new BufferedReader ( new InputStreamReader(System.in));
        InetAddress ip = InetAddress.getByName("localhost");
        byte out_data[] = new byte[2048];
            
        System.out.println("Server waiting for Client request.........");
            
        //Receiving Username from Client 
        DatagramPacket clientPacket = new DatagramPacket(in_data, in_data.length);
        serverSocket.receive(clientPacket);
        String username = new String(clientPacket.getData(),0,clientPacket.getLength());
        System.out.println("User "+ username + " is Connecting ....");
        System.out.println(" ");

       //RC4 Decryption & Encryption
        String plaintext = h.Key1(pg.getP(), pg.getG());  //get p,g, g^a modp
            System.out.println("P:" + pg.getP());
            System.out.println("g:" + pg.getG());
            System.out.println("p ,g , g^a Mod P: "+ plaintext);
        byte[] plainBytes = plaintext.getBytes();
        
        String hashedKey = Host.HashedPassword("123456");  //Secret Key 
        Key key = new SecretKeySpec(Hex.decode(hashedKey), "RC4"); //String to key conversion using Hex.decode to convert to byte []
        
        // Create Cipher instance and initialize it to encrytion mode
        Cipher rc4 = Cipher.getInstance("RC4");  // Transformation of the algorithm
        rc4.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherBytes = rc4.doFinal(plainBytes);
        
        String encoded = encodeBase64(cipherBytes);
        //String decoded = decodeBase64(encoded);
        /*Test
        String hashedKey1 = Host.HashedPassword("1111111");   //Testing with diff Secret Key 
        System.out.println(hashedKey1);
        Key key1 = new SecretKeySpec(Hex.decode(hashedKey1), "RC4");
        System.out.println("Key1 " + key1); */
        //decrypt((SecretKey) key, rc4, ciphertextBytes);   
        
        //Sending out ----->E(H(pw),p,g,g^a Mod p
        InetAddress ip1 = clientPacket.getAddress();   //get Client's Address
        int port = clientPacket.getPort();
        
        String E1 = Base64.getEncoder().encodeToString(encrypt(plaintext, (SecretKey) key, rc4));
        out_data = E1.getBytes();
        DatagramPacket encryptedPacket1 = new DatagramPacket(out_data,out_data.length,ip1,port);
        serverSocket.send(encryptedPacket1);
        System.out.println("SENDING E(H(Pw),p ,g,g^a Modp)TO CLIENT..........");
        System.out.println();
        
        //Receiving Encrypted --->(E(H(pw), g^b Modp))
        serverSocket.receive(clientPacket);
	String EncryptedMessage = new String(clientPacket.getData(),0,clientPacket.getLength());
	System.out.println("RECEIVED ENCRYPTED E(H(pw),g^b ModP)): " + EncryptedMessage);

        //Decrypting Message ---> E(H(pw),g^b Modp) 
        byte [] EncryptedBytes = Base64.getDecoder().decode(EncryptedMessage.getBytes());
        
        rc4.init(Cipher.DECRYPT_MODE, key);
        String Decrypted_Message = decrypt((SecretKey) key, rc4, EncryptedBytes);
        
        System.out.println("");
        //ReadLine - Encrypted Message  
        String line = Decrypted_Message;
        BigInteger Ans; 
        Ans = BigInteger.valueOf(Long.valueOf(Decrypted_Message));  //g^b ModP
        
       //--------------- Compute Share Key here ----------------
        shareKey = Ans.modPow(exponent_a, BigInteger.valueOf(pg.getP()));
        System.out.println("Ans: "+ Ans);
        System.out.println("Exponent a: "+ exponent_a);
        System.out.println("P: "+ pg.getP());
        System.out.println("G: "+ pg.getG());
        System.out.println("SHARE KEY(Host) in Digit :" + shareKey);
         
        String sKey = String.valueOf(shareKey);  //Convert skey to String 
        System.out.println("SHARE KEY(Host) : "+ HashedPassword(sKey));
        
        System.out.println("");
        //Encrypting NA --> E(H(K),NA)
        BigInteger NA = BigInteger.valueOf(getRandomNA());
        String plaintext2 = getNonce(NA);   //Get Nonce
        System.out.println("[NOT SEND] - NA value to check: "+ plaintext2);
        String hashedKey2 = Host.HashedPassword(sKey);  //Use Secret Key = ShareKey K 
        
        //Conver KeyString to Key 
        Key key2 = new SecretKeySpec(Hex.decode(hashedKey2), "RC4");  //shareKey K 
        rc4.init(Cipher.ENCRYPT_MODE, key2);    //Encrypt with shareKey K 
        //byte[] cipherBytes2 = rc4.doFinal(plainBytes2);
        
        //Sending out Encrypted NA --->E(K,NA) 
	String E2 = Base64.getEncoder().encodeToString(encrypt(plaintext2, (SecretKey) key2, rc4));
        out_data = E2.getBytes();
	DatagramPacket step4 = new DatagramPacket(out_data,out_data.length,ip,port);
	System.out.println("SENDING ENCRYPTED E(K,NA) TO CLIENT .............");
	System.out.println(" ");
        serverSocket.send(step4);
        
        //Receiving In Encrypted --->E(K,NA+1, NB) 
        serverSocket.receive(clientPacket);
        String Encrypted_Step5 = new String(clientPacket.getData(),0,clientPacket.getLength());
	System.out.println("RECEIVED ENCRYPTED E(K,NA+1,NB): " + Encrypted_Step5);
	
        //Decryping --->E(K,NA+1,NB) from Client 
        //Convert Encrypted text to Bytes
        byte [] EncryptedBytes2 = Base64.getDecoder().decode(Encrypted_Step5.getBytes());
        rc4.init(Cipher.DECRYPT_MODE, key2);   //Encrypt with ShareKey K 
        String Decrypted_step5 = decrypt((SecretKey) key2, rc4, EncryptedBytes2);  //Using K2 to Decrypt

        //Check the response NA+1 ?
        int nAPlus = 0; 
        int bb = 0;
        String line1 = Decrypted_step5;   //NA+1, NB from Client
        String[] nonces = line1.trim().split("[\\W]+");
        for ( int i = 0; i < line1.length(); i++)
        {
           nAPlus = Integer.valueOf(nonces[0]);   //get NA+1
           bb = Integer.valueOf(nonces[1]);       //get NB 
        }
        int bbb = bb+1; 
        
        System.out.println("");
        String step6_text = String.valueOf(bbb) ;      //Get nB+1
        System.out.println("[NOT SEND]- NB+1 for Client to Check: "+  step6_text);
        
        //Sending out Encrypted NB+1 ------>E(K,NB+1) 
        rc4.init(Cipher.ENCRYPT_MODE, key2);      //Encrypt with ShareKey K 
        String E3 = Base64.getEncoder().encodeToString(encrypt(step6_text, (SecretKey) key2, rc4));
        out_data = E3.getBytes();
        DatagramPacket step5 = new DatagramPacket(out_data,out_data.length,ip,port);
        System.out.println("SENDING ENCRYPTED E(K,NB+1) TO CLIENT ...........");  //Send NB+1 to Bob Check
        System.out.println(" ");
        serverSocket.send(step5);
        
        //Authentication User 
        boolean authenticateUser  = CheckCorrectNonceA(nAPlus); //Authentication 
        if( authenticateUser == true)
        {
            System.out.println("NA+1 is Correct,Waiting for Client's Check NB+1...");
            Scanner sc = new Scanner(System.in);
            
            //Integrity Check H Value 
            while(true)
            {
                //Receiving  Encrypted--->E(K,M||Hash)
                serverSocket.receive(clientPacket);
                String Encrypted_mh = new String(clientPacket.getData(),0,clientPacket.getLength());
                System.out.println("\nServer(receiving) E(K,M||Hash): " + Encrypted_mh);
                
                //Decrypting--->(K,M||Hash) ----> Client's Message||Hash
               byte [] Encrypted_MH = Base64.getDecoder().decode(Encrypted_mh.getBytes());
               rc4.init(Cipher.DECRYPT_MODE, key2);   //Encrypt with ShareKey K 
                String RC4_Decrypted_MH = decrypt((SecretKey) key2, rc4, Encrypted_MH);
                String decrypted_MH= RC4_Decrypted_MH.substring(0, RC4_Decrypted_MH.indexOf("||"));
		String decrypted_client_m = decrypted_MH.substring(decrypted_MH.lastIndexOf("||") + 1);
                String decrypted_client_h = RC4_Decrypted_MH.substring(RC4_Decrypted_MH.lastIndexOf("||") + 2);
                
                System.out.println("Decrypted client Message: " + decrypted_client_m);
		System.out.println("Decrypted client Hash H : " + decrypted_client_h);
		System.out.println();
                
                //Integrity Check (H)= H(K||M||K) from Client
                String K_M_K = key2 + decrypted_client_m + key2;      //Using Server Share Key
                String Decrypted_Server_hash = HashedPassword(K_M_K);            //Hash(K||M||K)
                System.out.println("NOT SEND - [Server H(K||M||K)] to check:" + Decrypted_Server_hash);
		
		String server_h = new String(Decrypted_Server_hash);  //Server's H
		String client_h = new String(decrypted_client_h);     //From Client's H

		if (client_h.equals(server_h))
		{
                    System.out.println("Result: Server H = Client H");
                    System.out.println("Decryption is Successful");
		} 
		else
		{
                    System.out.println("Result: Server H DIFFERENT as Client H");
                    System.out.println("Communication error");
                    System.out.println("Rejected!");
		}
                
                //Sending Message to Client 
                System.out.print("\nServer(sending) PLAINTEXT: ");
		String serverdata = sc.nextLine();
                out_data = serverdata.getBytes();
                DatagramPacket send_EncryptedMessage = new DatagramPacket(out_data,out_data.length,ip,port);
                
                if(serverdata.equalsIgnoreCase("exit"))
                {
                    System.out.println("CONNECTED ENDED BY SERVER!");
                    System.exit(0);
                }  
                
                //Integrity Check (H) for Server Message 
		String K_M_K2 = key2 + serverdata + key2;   
                String Server_H = HashedPassword(K_M_K2);    //Server's H
                System.out.println("NOT SEND - [Server H(K||M||K)] for Client to check:" + Server_H); //Server's H
                    
                //Now Comupte C = E(K,M||Hash)
                String C = serverdata+ "||" + Server_H;  //M||Hash 
                //Encrypted --->E(K,M||Hash) 
                rc4.init(Cipher.ENCRYPT_MODE, key2);      //Encrypt with ShareKey K 
                String Encrypted_M_H = Base64.getEncoder().encodeToString(encrypt(C,(SecretKey) key2, rc4));
                System.out.println("Sending Encrypted E(K,M||Hash): "+ Encrypted_M_H);         
                    
                //Sending out -->Encrypted E(K,M||Hash)
                out_data = Encrypted_M_H.getBytes();
                DatagramPacket send_c = new DatagramPacket(out_data,out_data.length,ip,port);  //Client's Port 
                serverSocket.send(send_c);           
            }
        }
        else if (authenticateUser == false)
        {
             System.out.println("LogIn failed");
            String Fail_login = "Host: LogIn failed!";
            //System.out.println("Client " + Fail_login + "Failed !");
            out_data = Fail_login.getBytes();
            DatagramPacket fail_message = new DatagramPacket(out_data,out_data.length,ip,port);
            serverSocket.send(fail_message);
            System.exit(0);             //Server Exit
            serverSocket.close();
        }
    }
}
//==========End of Class Host========== 
class pgGenerator {
    private Long pvalue,gvalue;
    String Hpassword; 
    public pgGenerator(){   //Default Constructor 
       
    }
    public pgGenerator(Long p, Long g){
        this.pvalue = p;
        this.gvalue = g;
    }
    public Long getPvalue() {
        return pvalue;
    }
    public void setPvalue(Long pvalue) {
        this.pvalue = pvalue;
    }

    public Long getGvalue() {
        return gvalue;
    }
    public void setGvalue(Long gvalue) {
        this.gvalue = gvalue;
    }
    public String getKey() { return this.Hpassword; } 
    
    public  void setP(Long p) { this.pvalue = p;}
    public  void setG(Long g) { this.gvalue = g; }

    public Long getP() { return this.pvalue; }    
    public Long getG() { return this.gvalue; }
  
    public void WritetoFile(String input)throws IOException {
       // Write to Alice.txt File
       Host h = new Host();
       String pStr = String.valueOf(pvalue);  
       String gStr = String.valueOf(gvalue);
       String pw = h.HashedPassword("123456");
       
       String output = pStr + "," + gStr +  "," + pw; 
       FileWriter writefile = new FileWriter("Alice.txt",true);
       
       writefile.write( output + System.lineSeparator());
       writefile.close();
    }
}




