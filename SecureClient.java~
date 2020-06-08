package com.company;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;

public class SecureClient {

    public static void main(String[] args) throws IOException {

        CryptoHelper crypto = new CryptoHelper();
        Socket clientSocket;
        DataOutputStream outToServer;
        DataInputStream inFromServer;
        byte[] serverPublicKey;
        // 4.1 HANDSHAKE
        while (true) {
            int port = Integer.parseInt(args[0]);
            clientSocket = new Socket("127.0.0.1", port);
            outToServer = new DataOutputStream(clientSocket.getOutputStream());
            inFromServer = new DataInputStream(clientSocket.getInputStream());

            byte[] certificate = sendMessage(outToServer, inFromServer);
            serverPublicKey = getPK(certificate);
            boolean verified = verify(certificate);
            if (!verified) {
                continue;
            }
            break;
        }
        int secret = crypto.generateSecret();
        byte[] secretEncrypted = crypto.encryptSecretAsymmetric(secret, serverPublicKey);
        sendSecret(secretEncrypted,outToServer);

        // 4.2 AUTHENTICATION
        byte[] authEncrypted = crypto.encryptSymmetric("bilkent cs421", secret);
        sendStartenc(outToServer);
        byte[] authResponse = sendAuth(authEncrypted,outToServer,inFromServer);
        String response = crypto.decryptSymmetric(authResponse,secret);
        System.out.println("\nAuth Repsonse: ");
        System.out.println(response);
        sendEndenc(outToServer);

        // 4.3 VIEW PUBLIC POSTS
        byte[] publicResponse = sendPublicOrPrivate(outToServer,inFromServer,true);
        response = new String(publicResponse);
        System.out.println("\nPublic Posts: ");
        System.out.println(response);

        // 4.4 VIEW PRIVATE MESSAGES
        sendStartenc(outToServer);
        byte[] privateResponse = sendPublicOrPrivate(outToServer,inFromServer,false);
        response = crypto.decryptSymmetric(privateResponse, secret);
        System.out.println("\nPrivate Messages: ");
        System.out.println(response);
        sendEndenc(outToServer);

        // 4.5 LOG OUT
        System.out.println("\nLogging out...");
        sendLogout(outToServer);
        inFromServer.close();
        outToServer.close();
        clientSocket.close();
    }

    public static byte[] getPK(byte[] certificate){
        String certString = new String(certificate);
        int pkStart = certString.indexOf("PK=")+3;
        int pkEnd = certString.indexOf("CA=");
        byte[] pk = new byte[pkEnd-pkStart];
        for(int i = pkStart; i<pkEnd; i++){
            pk[i-pkStart] = certificate[i];
        }
        return pk;
    }
    public static boolean verify(byte[] certificate) throws UnsupportedEncodingException {
        String certString = new String(certificate);
        int len = certificate.length;

        int caStart = certString.indexOf("CA=") + 3;
        int caEnd = certString.indexOf("SIGNATURE=");
        int sigStart = caEnd + 10;
        int sigLen = len - sigStart;
        byte[] signature = new byte[sigLen];
        for(int i=sigStart; i<len; i++){
            signature[i-sigStart] = certificate[i];
        }
        String ca = certString.substring(caStart,caEnd);
        CryptoHelper crypto = new CryptoHelper();
        boolean verified = crypto.verifySignature(certificate,signature,ca);
        if (verified)
            System.out.println("Successfully verified!");
        else
            System.out.println("Verification unsuccessful!");
        return verified;
    }

    public static byte[] sendMessage(DataOutputStream outToServer, DataInputStream inFromServer) throws IOException {
        outToServer.write(concatenateBytes("HELLOxxx".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
        outToServer.flush();
        byte[] typeIn = new byte[8];
        byte[] lengthIn = new byte[4];
        for(int i=0; i<8; i++){
            typeIn[i] = inFromServer.readByte();
        }
        String type = new String(typeIn);
        for(int i=0; i<4;i++){
            lengthIn[i] = inFromServer.readByte();
        }
        int length = ByteBuffer.wrap(lengthIn).getInt();
        byte[] dataIn = new byte[length];
        for (int i=0; i<length; i++){
            dataIn[i] = inFromServer.readByte();
        }
        return dataIn;
    }
    public static void sendSecret(byte[] secretEncrypted, DataOutputStream outToServer) throws IOException {
        byte[] temp = concatenateBytes("SECRETxx".getBytes(),ByteBuffer.allocate(4).putInt(secretEncrypted.length).array());
        outToServer.write(concatenateBytes(temp, secretEncrypted));
        outToServer.flush();
    }
    public static void sendStartenc( DataOutputStream outToServer) throws IOException {
        outToServer.write(concatenateBytes("STARTENC".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
        outToServer.flush();
    }
    public static void sendEndenc( DataOutputStream outToServer) throws IOException {
        outToServer.write(concatenateBytes("ENDENCxx".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
        outToServer.flush();
    }
    public static void sendLogout( DataOutputStream outToServer) throws IOException {
        outToServer.write(concatenateBytes("LOGOUTxx".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
        outToServer.flush();
    }
    public static byte[] sendPublicOrPrivate(DataOutputStream outToServer, DataInputStream inFromServer, boolean ispublic) throws IOException {
        String sendType = "PRIVATEx";
        if(ispublic)
            sendType = "PUBLICxx";
        outToServer.write(concatenateBytes(sendType.getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
        byte[] typeIn = new byte[8];
        byte[] lengthIn = new byte[4];
        for(int i=0; i<8; i++){
            typeIn[i] = inFromServer.readByte();
        }
        String type = new String(typeIn);
        for(int i=0; i<4;i++){
            lengthIn[i] = inFromServer.readByte();
        }
        int length = ByteBuffer.wrap(lengthIn).getInt();
        byte[] dataIn = new byte[length];
        for (int i=0; i<length; i++){
            dataIn[i] = inFromServer.readByte();
        }
        return dataIn;
    }

    public static byte[] sendAuth(byte[] authEncrypted, DataOutputStream outToServer, DataInputStream inFromServer) throws IOException {
        byte[] temp = concatenateBytes("AUTHxxxx".getBytes(),ByteBuffer.allocate(4).putInt(authEncrypted.length).array());
        outToServer.write(concatenateBytes(temp,authEncrypted));
        outToServer.flush();
        byte[] typeIn = new byte[8];
        byte[] lengthIn = new byte[4];
        for(int i=0; i<8; i++){
            typeIn[i] = inFromServer.readByte();
        }
        String type = new String(typeIn);
        for(int i=0; i<4;i++){
            lengthIn[i] = inFromServer.readByte();
        }
        int length = ByteBuffer.wrap(lengthIn).getInt();
        byte[] dataIn = new byte[length];
        for (int i=0; i<length; i++){
            dataIn[i] = inFromServer.readByte();
        }
        return dataIn;

    }

    public static byte[] concatenateBytes(byte[] a, byte[] b){
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
