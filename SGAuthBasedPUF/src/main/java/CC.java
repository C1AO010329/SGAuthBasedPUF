import com.alibaba.fastjson.JSON;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;


public class CC {
    public HashSet<String> IDiSet = new HashSet<>();
    public HashSet<String> IDgSet = new HashSet<>();
    public HashMap<String,INFO_SN> OTIDiPreviousDatabase;
    public HashMap<String,INFO_SN> OTIDiCurrentDatabase;
    public byte[] MSK;

    public CC() throws Exception{
        //  生成并存储主密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();
        this.MSK = key.getEncoded();


        this.OTIDiPreviousDatabase = new HashMap<>();
        this.OTIDiCurrentDatabase = new HashMap<>();
    }


    public boolean CheckIDi(RegiRequest regiRequest) throws Exception {
        if (IDiSet.contains(myUtil.encodeHexString(regiRequest.ID))){
            throw new Exception("Node Existed!");
        }
        else {
            IDiSet.add(myUtil.encodeHexString(regiRequest.ID));
            return false;
        }

    }
    public boolean CheckIDg(RegiRequest regiRequest) throws Exception {
        if (IDgSet.contains(myUtil.encodeHexString(regiRequest.ID))){
            throw new Exception("Node Existed!");
        }
        else {
            IDgSet.add(myUtil.encodeHexString(regiRequest.ID));
            return false;
        }

    }
    //  生成密钥Ki、Kg
    public byte[] generateNodeKey(RegiRequest RegiRequest) throws Exception{
        if (RegiRequest.RegReq!=null){
            //  生成用于计算主密钥的数组
            byte[] temp = new byte[RegiRequest.ID.length+this.MSK.length];
            System.arraycopy(RegiRequest.ID,0,temp,0, RegiRequest.ID.length);
            System.arraycopy(this.MSK,0,temp, RegiRequest.ID.length,this.MSK.length);

            //  生成Key
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(temp);
            return messageDigest.digest();
        }

        else {
            throw new IllegalArgumentException("Invalid Request");
        }
    }
    //  生成挑战Ci
    public byte[] generateCi(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] Ci = new byte[myUtil.C_LENGTH];
        secureRandom.nextBytes(Ci);
        return Ci;
    }
    public byte[] generateNodeKey(byte[] ID) throws Exception{
        byte[] temp = new byte[ID.length+this.MSK.length];
        System.arraycopy(ID,0,temp,0, ID.length);
        System.arraycopy(this.MSK,0,temp, ID.length,this.MSK.length);
        //  生成Key
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(temp);
        return messageDigest.digest();
    }
    public byte[] generateOTIDi(){
        SecureRandom sr = new SecureRandom();
        byte[] OTIDi = new byte[8];
        sr.nextBytes(OTIDi);
        return OTIDi;
    }
    public byte[] storeOTIDi(INFO_SN InfoSN){
        SecureRandom sr = new SecureRandom();
        byte[] OTIDi = new byte[myUtil.OTID_LENGTH];
        System.arraycopy(generateOTIDi(),0,OTIDi,0,OTIDi.length);

        this.OTIDiCurrentDatabase.put(myUtil.encodeHexString(OTIDi), InfoSN);
        return OTIDi;
    }

    public void updateOTIDi(byte[] OTIDiPrevious,byte[] OTIDiNew){
        if(this.OTIDiCurrentDatabase.containsKey(myUtil.encodeHexString(OTIDiPrevious))){
            INFO_SN infoSn  = this.OTIDiCurrentDatabase.get(myUtil.encodeHexString(OTIDiPrevious));

            this.OTIDiCurrentDatabase.put(myUtil.encodeHexString(OTIDiNew), infoSn);
            this.OTIDiCurrentDatabase.remove(myUtil.encodeHexString(OTIDiPrevious));
            this.OTIDiPreviousDatabase.put(myUtil.encodeHexString(OTIDiPrevious),infoSn);
        } else if (this.OTIDiPreviousDatabase.containsKey(myUtil.encodeHexString(OTIDiPrevious))) {
            INFO_SN infoSn  = this.OTIDiPreviousDatabase.get(myUtil.encodeHexString(OTIDiPrevious));
            for (String s:this.OTIDiCurrentDatabase.keySet()) {
                if (Objects.equals(this.OTIDiCurrentDatabase.get(s).toString(), infoSn.toString()))
                    this.OTIDiCurrentDatabase.remove(s);

            }
            this.OTIDiCurrentDatabase.put(myUtil.encodeHexString(OTIDiNew), infoSn);
            this.OTIDiPreviousDatabase.put(myUtil.encodeHexString(OTIDiPrevious),infoSn);


        }
    }

    public Message3 generateMsg3(Message2 Msg2) throws Exception{
        Message3 Msg3 = new Message3();
        long Timestamp3 = System.currentTimeMillis();
        Msg3.Timestamp3 = Timestamp3;
        System.arraycopy(myUtil.longToBytes(Timestamp3),0,Msg3.T3b,0,Long.BYTES);

        byte[] OTIDi = Msg2.Msg1.OTIDi;
        INFO_SN info_sn = new INFO_SN();
        if (this.OTIDiCurrentDatabase.containsKey(myUtil.encodeHexString(OTIDi))){
            info_sn = this.OTIDiCurrentDatabase.get(myUtil.encodeHexString(OTIDi));
        }
        else if(this.OTIDiPreviousDatabase.containsKey(myUtil.encodeHexString(OTIDi))){
            info_sn = this.OTIDiPreviousDatabase.get(myUtil.encodeHexString(OTIDi));

        }

        if(myUtil.isAllZero(info_sn.Ci)){
            throw new Exception("无法查询到此OTID");
        }

        byte[] r1r2 = myUtil.xorByteArrays(info_sn.IDi, Msg2.Msg1.D1);
        byte[] Ki = generateNodeKey(info_sn.IDi);
        byte[] OrdiD2Star = new byte[myUtil.ID_LENGTH+myUtil.ID_LENGTH+myUtil.KEY_LENGTH+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH+Long.BYTES];
        System.arraycopy(info_sn.IDi,0,OrdiD2Star,0,myUtil.ID_LENGTH);
        System.arraycopy(Msg2.IDg, 0, OrdiD2Star, myUtil.ID_LENGTH, myUtil.ID_LENGTH);
        System.arraycopy(Ki, 0,OrdiD2Star, myUtil.ID_LENGTH+myUtil.ID_LENGTH,myUtil.KEY_LENGTH);
        System.arraycopy(r1r2,0,OrdiD2Star, myUtil.ID_LENGTH+myUtil.ID_LENGTH+myUtil.KEY_LENGTH,r1r2.length);
        System.arraycopy(Msg2.Msg1.T1b,0, OrdiD2Star,myUtil.ID_LENGTH+myUtil.ID_LENGTH+myUtil.KEY_LENGTH+r1r2.length,Long.BYTES);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(OrdiD2Star);
        byte[] D2Star = messageDigest.digest();

         if(true){
             byte[] Kg = generateNodeKey(Msg2.IDg);
             byte[] r3r4LIg = myUtil.xorByteArrays(Msg2.D3,Kg);
             byte[] r3r4b = new byte[myUtil.RAND_LENGTH*2];
             System.arraycopy(r3r4LIg,0,r3r4b,0,r3r4b.length);
             byte[] OrdiD4Star = new byte[myUtil.ID_LENGTH+myUtil.KEY_LENGTH+ r3r4b.length];
             System.arraycopy(Msg2.IDg,0,OrdiD4Star,0,Msg2.IDg.length);
             System.arraycopy(Kg,0,OrdiD4Star,Msg2.IDg.length,Kg.length);
             System.arraycopy(r3r4b,0, OrdiD4Star,Msg2.IDg.length+Kg.length,r3r4b.length);

             MessageDigest msgDigestD4 = MessageDigest.getInstance("SHA-256");
             msgDigestD4.update(OrdiD4Star);
             byte[] D4Star = new byte[256/8];
             System.arraycopy(msgDigestD4.digest(),0,D4Star,0,D4Star.length);

             if(true){
                 byte[] OTIDinew = new byte[myUtil.OTID_LENGTH];
                 SecureRandom secureRandom = new SecureRandom();
                 secureRandom.nextBytes(OTIDinew);
                 System.arraycopy(OTIDinew,0,Msg3.OTIDinew,0,myUtil.OTID_LENGTH);
                 updateOTIDi(OTIDi,OTIDinew);

                 long r5 = Math.abs(secureRandom.nextLong());
                 System.out.println("r5: "+r5);
                 byte[] r5b = myUtil.longToBytes(r5);
                 System.arraycopy(r5b,0,Msg3.r5b,0,Msg3.r5b.length);

                 byte[] OrdiSessionKey = new byte[myUtil.ID_LENGTH+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH];
                 System.arraycopy(Msg2.IDg,0,OrdiSessionKey,0,myUtil.ID_LENGTH);
                 System.arraycopy(Msg2.Msg1.r1,0,OrdiSessionKey,myUtil.ID_LENGTH,myUtil.RAND_LENGTH);
                 System.arraycopy(Msg2.r3,0,OrdiSessionKey,myUtil.ID_LENGTH+myUtil.RAND_LENGTH,myUtil.RAND_LENGTH);
                 System.arraycopy(r5b,0,OrdiSessionKey,myUtil.ID_LENGTH+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH,myUtil.RAND_LENGTH);

                 MessageDigest messageDigest1 = MessageDigest.getInstance("MD5");
                 messageDigest1.update(OrdiSessionKey);
                 byte[] SessionKey = messageDigest1.digest();

                 byte[] r1r5b = new byte[myUtil.RAND_LENGTH*2];
                 System.arraycopy(Msg2.Msg1.r1, 0, r1r5b, 0, myUtil.RAND_LENGTH);
                 System.arraycopy(r5b, 0, r1r5b, myUtil.RAND_LENGTH, myUtil.RAND_LENGTH);

                 byte[] D5 = myUtil.xorByteArrays(Msg2.r3,r1r5b);
                 System.arraycopy(D5,0,Msg3.D5,0,Msg3.D5.length);

                 byte[] D6 = new byte[myUtil.RAND_LENGTH+myUtil.RAND_LENGTH+OTIDinew.length+ myUtil.C_LENGTH];
                 byte[] OrdiD6 = new byte[D6.length];
                 System.arraycopy(Msg2.r3, 0, OrdiD6, 0, myUtil.RAND_LENGTH);
                 System.arraycopy(r5b, 0, OrdiD6, myUtil.RAND_LENGTH, myUtil.RAND_LENGTH);
                 System.arraycopy(OTIDinew, 0, OrdiD6, myUtil.RAND_LENGTH+myUtil.RAND_LENGTH, OTIDinew.length);
                 System.arraycopy(info_sn.Ci, 0, OrdiD6, myUtil.RAND_LENGTH+myUtil.RAND_LENGTH+OTIDinew.length,myUtil.C_LENGTH);
                 System.arraycopy(myUtil.xorByteArrays(Msg2.Msg1.r2, OrdiD6),0,D6,0,Math.max(OrdiD6.length,Msg2.Msg1.r2.length));
                 System.arraycopy(D6,0,Msg3.D6,0,Msg3.D6.length);

                 byte[] OrdiD7 = new byte[myUtil.ID_LENGTH+myUtil.KEY_LENGTH+myUtil.RAND_LENGTH+ SessionKey.length];
                 System.arraycopy(Msg2.IDg,0,OrdiD7,0,myUtil.ID_LENGTH);
                 System.arraycopy(Kg,0,OrdiD7,myUtil.ID_LENGTH,myUtil.KEY_LENGTH);
                 System.arraycopy(Msg2.r4,0,OrdiD7,myUtil.ID_LENGTH+myUtil.KEY_LENGTH,myUtil.RAND_LENGTH);
                 System.arraycopy(SessionKey,0,OrdiD7,myUtil.ID_LENGTH+myUtil.KEY_LENGTH+myUtil.RAND_LENGTH,SessionKey.length);


                 MessageDigest messageDigest2 = MessageDigest.getInstance("SHA-256");
                 messageDigest2.update(OrdiD7);
                 byte[] D7 = new byte[messageDigest2.getDigestLength()];
                 System.arraycopy(messageDigest2.digest(),0,D7,0,D7.length);
                 Msg3.D7 = new byte[messageDigest2.getDigestLength()];
                 System.arraycopy(D7,0,Msg3.D7,0,D7.length);

                 byte[] OrdiD8 = new byte[myUtil.ID_LENGTH+ Ki.length+myUtil.RAND_LENGTH+ SessionKey.length];
                 System.arraycopy(info_sn.IDi,0,OrdiD8,0,myUtil.ID_LENGTH);
                 System.arraycopy(Ki,0,OrdiD8,myUtil.ID_LENGTH,myUtil.KEY_LENGTH);
                 System.arraycopy(Msg2.Msg1.r2,0,OrdiD8,myUtil.ID_LENGTH+myUtil.KEY_LENGTH,myUtil.RAND_LENGTH);
                 System.arraycopy(SessionKey,0,OrdiD8,myUtil.ID_LENGTH+myUtil.KEY_LENGTH+myUtil.RAND_LENGTH,SessionKey.length);
                 MessageDigest messageDigest3 = MessageDigest.getInstance("SHA-256");
                 messageDigest3.update(OrdiD8);
                 byte[] D8 = new byte[messageDigest3.getDigestLength()];
                 System.arraycopy(messageDigest3.digest(),0,D8,0,D8.length);
                 Msg3.D8 = new byte[messageDigest3.getDigestLength()];
                 System.arraycopy(D8,0,Msg3.D8,0,D8.length);
                 System.arraycopy(OTIDinew,0,Msg3.OTIDinew,0,myUtil.OTID_LENGTH);
                 return Msg3;
             }
         }
        return null;
    }

}
class INFO_SN {
    byte[] IDi = new byte[8];
    byte[] Ci = new byte[myUtil.C_LENGTH];
    byte[] Ri = new byte[myUtil.R_LENGTH];
}
class INFO_RET_SN{
    byte[] IDi;
    byte[] Ki;
    byte[] OTIDi;
}