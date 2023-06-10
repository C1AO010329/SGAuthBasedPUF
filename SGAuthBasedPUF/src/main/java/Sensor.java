import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Sensor {
    byte[] IDi = new byte[myUtil.ID_LENGTH];
    byte[] IDg = new byte[myUtil.ID_LENGTH];
    byte[] Ci = new byte[myUtil.C_LENGTH];
    byte[] Ri = new byte[myUtil.R_LENGTH];
    byte[] OTIDi = new byte[myUtil.OTID_LENGTH];
    byte[] Ki = new byte[myUtil.KEY_LENGTH];
    private final SecretKey MasterKey;
    public byte[] r1b = new byte[Long.BYTES];
    public byte[] r2b = new byte[Long.BYTES];
    public byte[] SessionKey = new byte[myUtil.KEY_LENGTH];

    public RegiRequest sensorRegiRequest;
    public Message1 message1;
    public Message4 message4;


    public Sensor() throws NoSuchAlgorithmException {
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(IDi);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HMACMD5");       // 用于作为PUF的密钥，仅有此用处。
        this.MasterKey = keyGenerator.generateKey();
        this.sensorRegiRequest = new RegiRequest();
        this.sensorRegiRequest.ID = this.IDi;
    }
    // 生成响应Ri(128bits)
    public byte[] generateRi(byte[] Ci) throws Exception{
        System.arraycopy(Ci,0,this.Ci,0,Ci.length);
        Mac mac = Mac.getInstance("HMACMD5");
        mac.init(MasterKey);
        mac.update(Ci);
        this.Ri = mac.doFinal();
        return this.Ri;
    }

    public void StoreKi(byte[] Ki){
        this.Ki = Ki;
    }

    public Message1 generateMsg1() throws Exception{
        Message1 Msg1 = new Message1();
        Msg1.Timestamp1 = System.currentTimeMillis();

        Msg1.T1b = myUtil.longToBytes(Msg1.Timestamp1);
        byte[] T1b = Msg1.T1b;

        SecureRandom sr = new SecureRandom();

        long r1 = Math.abs(sr.nextLong());
        System.out.println("r1: "+r1);
        byte[] r1b = new byte[8];
        System.arraycopy(myUtil.longToBytes(r1),0,r1b,0,r1b.length);
        System.arraycopy(myUtil.longToBytes(r1),0,this.r1b,0,r1b.length);
        Msg1.r1 = r1b;

        long r2 = Math.abs(sr.nextLong());
        System.out.println("r2: "+r2);
        byte[] r2b = new byte[8];
        System.arraycopy(myUtil.longToBytes(r2),0,r2b,0,r2b.length);
        System.arraycopy(myUtil.longToBytes(r2),0,this.r2b,0,r2b.length);
        Msg1.r2 = r2b;

        byte[] r1r2b = new byte[r1b.length+ r2b.length];
        System.arraycopy(r1b,0, r1r2b,0, r1b.length);
        System.arraycopy(r2b,0, r1r2b, r1b.length, r2b.length);
        Msg1.D1 = myUtil.xorByteArrays(this.IDi, r1r2b);

        byte[] OrdiD2 = new byte[this.IDi.length+this.IDg.length+this.Ki.length+ r1r2b.length+T1b.length];
        System.arraycopy(this.IDi, 0, OrdiD2, 0, this.IDi.length);
        System.arraycopy(this.IDg, 0, OrdiD2, this.IDi.length, this.IDg.length);
        System.arraycopy(this.Ki, 0, OrdiD2, this.IDi.length+ this.IDg.length, Ki.length);
        System.arraycopy(r1r2b, 0, OrdiD2, this.IDi.length+this.IDg.length+this.Ki.length, r1r2b.length);
        System.arraycopy(T1b, 0, OrdiD2, this.IDi.length+this.IDg.length+this.Ki.length+ r1r2b.length, T1b.length);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(OrdiD2);
        Msg1.D2 = messageDigest.digest();

        System.arraycopy(this.OTIDi,0,Msg1.OTIDi,0,myUtil.OTID_LENGTH);

        this.message1 = Msg1;

        return Msg1;
    }
    public void dealMsg4(Message4 Msg4) throws Exception{
        byte[] r3r5OTIDnew = new byte[Msg4.D6.length];
        this.message4 = Msg4;
        System.arraycopy(myUtil.xorByteArrays(this.message1.r2,Msg4.D6),0,r3r5OTIDnew,0,r3r5OTIDnew.length);

        byte[] r3r5b = new byte[myUtil.RAND_LENGTH+myUtil.RAND_LENGTH];
        System.arraycopy(r3r5OTIDnew,0,r3r5b,0,r3r5b.length);

        byte[] OrdiSessionKey = new byte[myUtil.ID_LENGTH+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH];
        System.arraycopy(this.IDg,0,OrdiSessionKey,0,IDg.length);
        System.arraycopy(this.message1.r1,0,OrdiSessionKey,IDg.length,myUtil.RAND_LENGTH);
        System.arraycopy(r3r5b,0,OrdiSessionKey,IDg.length+myUtil.RAND_LENGTH,myUtil.RAND_LENGTH+myUtil.RAND_LENGTH);
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] SessionKey = new byte[myUtil.KEY_LENGTH];
        messageDigest.update(OrdiSessionKey);
        System.arraycopy(Msg4.OTIDinew,0,this.OTIDi,0,myUtil.OTID_LENGTH);

        System.arraycopy(messageDigest.digest(),0,SessionKey,0,SessionKey.length);
        System.arraycopy(SessionKey,0,this.SessionKey,0,SessionKey.length);

    }
}
