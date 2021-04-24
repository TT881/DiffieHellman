# DiffieHellman
In order to Run, I had imported external jar File -->"import bwmorg.bouncycastle.util.encoders.Hex;" in my Library for RC4 Encryption/Decryption.
If cannot run, Kindly Download & import .jar file from the below link. 
 
http://www.java2s.com/Code/Jar/b/Downloadbouncycastlejar.htm

There is also a Video attached -->"A1_Sample_Run" to show how the program runs. 

- Execute Host.java first   
 (Host will automatically used Hash("123456") generate Hashed Password file named "Alice.txt")  
- For Client, use Correct password = 123456 to Run   
- Server(Host) is using "localhost" ip address 
- Bob(Client) is using Port no: "1234" for Communication 
------------------------------------------------------------------------------------

Steps
-------
1. Execute Host.java, It will generate a [p,g,H(Password)file] named --> "Alice.txt"
   Will display Server waiting for Client request.........

2. Execute Client.java , 
It will ask to Enter - User name & Password
Use password =  123456 to Run 

3. Host will Send E(H(PW),p,g,g^a Mod p)) to Client 
   Above messsage is Encrypted Using Key - H(Pw)   <-------- Host's Key

4. Once Client Received E(H(Pw),p,g^a Mod p)) 
   It Will Decrypt back to - Plain Text and get a. <----------Client's Key

5. Client Will Send Encrypt E(H(Pw), g^b Mod p)) to Host 
   Using key - H(Pw) <-- Password is Entered One 

6. Once Host Received, 
   Will Decrypt Back to - Plain Text and get b. 

7. Host will Send E(K,NA) to Client 
   This time, Encrypted with K = H(g^ab Modp) <------------Host's Share Key 

//Authentication Step 
8. Client will Decrypt E(K,NA) and get NA  
   Client Send E(K, NA+1, NB ) to Host  
   Using Key - H(g^ab Modp)   <----------------------------Client's Share Key 

9. Host will Decrypt E(K,NA+1,NB) 
   Will check NA & NA+1 ?     <----------- If NA+1 = Correct Nonce , Then Response Success! 
   Send E(K,NB+1) to Client 

10. Client will Decrypt E(K,NB) 
    - Check NB & NB+1 ?     <------------If NB+1 = Correct Nonce , Then Hand Shake is Successful! 

//Can Start Communication Now .........
11. Whenever client send a message, it will compute H = K||M||K and C = M||h, then send encrypted with ShareKey K E(K,M||h) and send C to server.

12. Once Server receive C, it will decrypt to get the M and then calculate it's own H and check with server H to see if there is any difference if no then server will aceppt the message. this go vice versa.

REFERENCES:  
The Website which i referenced from online while building my Assn1
-------------------------------------------------------------------
RC4 Encryption/Decryption Algorithm with Own Secret key - https://stackoverflow.com/questions/26722584/convert-string-to-key-in-java-for-rc4-encryption

BigInteger modPow()- https://www.geeksforgeeks.org/biginteger-modpow-method-in-java/

BigInteger.probablePrime() - https://www.tutorialspoint.com/java/math/biginteger_probableprime.htm 

SHA-1 Hash Function- https://www.geeksforgeeks.org/sha-1-hash-in-java/

