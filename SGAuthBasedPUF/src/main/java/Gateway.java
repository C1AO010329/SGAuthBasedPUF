import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Gateway {
    public byte[] IDg = new byte[myUtil.ID_LENGTH];
    public byte[] LocationIdentifier = new byte[myUtil.LID_LENGTH];
    public byte[] Kg = new byte[myUtil.KEY_LENGTH];

    public byte[] r3b = new byte[myUtil.RAND_LENGTH];
    public byte[] r4b = new byte[myUtil.RAND_LENGTH];

    public RegiRequest gatewayRegiRequest;
    public Message1 message1;
    public Message2 message2;
    public Message3 message3;
    public Message4 message4;

    public byte[] SessionKey = new byte[myUtil.KEY_LENGTH];

    public Gateway(){
        SecureRandom secureRandom = new SecureRandom();
        this.gatewayRegiRequest = new RegiRequest();
        secureRandom.nextBytes(this.IDg);
        this.gatewayRegiRequest.ID = this.IDg;
        secureRandom.nextBytes(LocationIdentifier);
    }

    public Message2 generateMsg2(Message1 Msg1) throws Exception{
        this.message1 = Msg1;
        long Timestamp2 = System.currentTimeMillis();
        Message2 Msg2 = new Message2();
        Msg2.Timestamp2 = Timestamp2;
       System.arraycopy( myUtil.longToBytes(Timestamp2),0,Msg2.T2b,0,Long.BYTES);

        Msg2.Msg1 = Msg1;
        Msg2.IDg = this.IDg;
        SecureRandom sr = new SecureRandom();
        long r3 = Math.abs(sr.nextLong());
        System.out.println("r3: "+r3);
        byte[] r3b = new byte[myUtil.RAND_LENGTH];
        System.arraycopy(myUtil.longToBytes(r3),0,r3b,0,r3b.length);
        System.arraycopy(r3b,0,this.r3b,0,r3b.length);
        System.arraycopy(r3b,0,Msg2.r3,0,r3b.length);

        long r4 = Math.abs(sr.nextLong());
        System.out.println("r4: "+r4);
        System.arraycopy(myUtil.longToBytes(r4),0,r4b,0,r4b.length);
        System.arraycopy(r4b,0,this.r4b,0,r4b.length);
        System.arraycopy(r4b,0,Msg2.r4,0,r4b.length);

        byte[] r3r4b = new byte[r3b.length+r4b.length];
        System.arraycopy(r3b, 0, r3r4b, 0, r3b.length);
        System.arraycopy(r4b, 0, r3r4b, r3b.length, r4b.length);

        byte[] OrdiD3 = new byte[24];
        System.arraycopy(r3r4b, 0, OrdiD3, 0, r3r4b.length);
        System.arraycopy(this.LocationIdentifier, 0, OrdiD3, r3r4b.length, this.LocationIdentifier.length);
        byte[] D3 = new byte[OrdiD3.length];
        Msg2.D3 = new byte[OrdiD3.length];
        System.arraycopy(myUtil.xorByteArrays(this.Kg, OrdiD3), 0, D3, 0, OrdiD3.length);
        System.arraycopy(myUtil.xorByteArrays(this.Kg, OrdiD3), 0, Msg2.D3, 0, OrdiD3.length);

        byte[] OrdiD4 = new byte[this.IDg.length+this.Kg.length+ r3r4b.length];
        System.arraycopy(this.IDg, 0, OrdiD4, 0, this.IDg.length);
        System.arraycopy(this.Kg, 0, OrdiD4, this.IDg.length, this.LocationIdentifier.length);
        System.arraycopy(r3r4b, 0, OrdiD4, this.IDg.length+this.Kg.length, r3r4b.length);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(OrdiD4);
        System.arraycopy(messageDigest.digest(),0,Msg2.D4,0,messageDigest.getDigestLength());

        this.message2 = Msg2;
        return Msg2;
    }

    public Message4 generateMsg4(Message3 Msg3) throws Exception{
        this.message3 = Msg3;
        long Timestamp4 = System.currentTimeMillis();
        Message4 Msg4 = new Message4();
        Msg4.Timestamp4 = Timestamp4;
        System.arraycopy(myUtil.longToBytes(Timestamp4),0,Msg4.T4b,0,Long.BYTES);

        byte[] r1r5b = new byte[myUtil.RAND_LENGTH*2];
        System.arraycopy(myUtil.xorByteArrays(r3b,Msg3.D5),0,r1r5b,0,r1r5b.length);

        byte[] OrdiSessionKey = new byte[myUtil.ID_LENGTH+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH];
        System.arraycopy(this.IDg,0,OrdiSessionKey,0,IDg.length);
        System.arraycopy(this.message1.r1,0,OrdiSessionKey,IDg.length,myUtil.RAND_LENGTH);
        System.arraycopy(message2.r3,0,OrdiSessionKey,IDg.length+myUtil.RAND_LENGTH,myUtil.RAND_LENGTH);
        System.arraycopy(Msg3.r5b,0,OrdiSessionKey,IDg.length+myUtil.RAND_LENGTH+myUtil.RAND_LENGTH,myUtil.RAND_LENGTH);

        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] SessionKey = new byte[myUtil.KEY_LENGTH];
        messageDigest.update(OrdiSessionKey);
        System.arraycopy(messageDigest.digest(),0,SessionKey,0,SessionKey.length);
        System.arraycopy(SessionKey,0,this.SessionKey,0,SessionKey.length);


        Msg4.D6 = new byte[Msg3.D6.length];
        System.arraycopy(Msg3.D6,0,Msg4.D6,0,Msg3.D6.length);
        Msg4.D8 = new byte[Msg3.D8.length];
        System.arraycopy(Msg3.D8,0,Msg4.D8,0,Msg3.D8.length);
        System.arraycopy(Msg3.OTIDinew,0,Msg4.OTIDinew,0,myUtil.OTID_LENGTH);
        this.message4 = Msg4;
        return Msg4;
    }
}
