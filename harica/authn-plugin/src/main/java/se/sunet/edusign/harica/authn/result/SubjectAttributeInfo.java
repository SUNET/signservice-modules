package se.sunet.edusign.harica.authn.result;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class SubjectAttributeInfo {
    SubjectDnType type;
    ASN1ObjectIdentifier oid;
    String dispName;
    String value;

    public SubjectAttributeInfo(ASN1ObjectIdentifier oid, String value) {
        this.oid = oid;
        this.value = value;

        type = SubjectDnType.getNameTypeForOid(oid);
        if (!type.equals(SubjectDnType.unknown)){
            dispName = type.getDispName();
        } else {
            dispName = OidName.getName(oid.getId());
        }
    }

    public SubjectAttributeInfo() {
    }

    public SubjectDnType getType() {
        return type;
    }

    public void setType(SubjectDnType type) {
        this.type = type;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }

    public void setOid(ASN1ObjectIdentifier oid) {
        this.oid = oid;
    }

    public String getDispName() {
        return dispName;
    }

    public void setDispName(String dispName) {
        this.dispName = dispName;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }


}
