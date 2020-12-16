pragma solidity >=0.4.25 <0.7.0;
pragma experimental ABIEncoderV2;

import "./Ownable.sol";

contract CA is Ownable {

    uint constant VERSION = 2;

    struct X509 {
        uint    version;
        string  valid_to;
        string  public_key;
        address issuer_id;
        string  subject_id;
        bool    exist;
        address wallet_owner;
    }

    // Certificates, referenced by cert hash
    mapping(string => X509) certs;
    mapping(uint => string) certs_map;
    uint certs_count;

    // Certificate Revocation List, referenced by cert hash
    mapping(string => bool) crl;
    mapping(uint => string) crl_map;
    uint crl_count;

    // Tiny hack to make solidity work...
    X509 NULL;

    constructor() public {
        certs_count = 0;
    }

    function enroll(string memory cert_hash,
                    string memory valid_to,
                    string memory public_key,
                    string memory subject_id)
        public onlyOwner returns(bool) {
        if (certs[cert_hash].exist) {
            return false;
        } else {
            X509 memory c = X509(VERSION,
                                 valid_to,
                                 public_key,
                                 owner,
                                 subject_id,
                                 true,
                                 msg.sender);
            certs[cert_hash] = c;
            crl[cert_hash] = false;
            certs_map[certs_count] = cert_hash;
            ++certs_count;
            return true;
        }
    }

    function revoke(string memory cert_hash)
        public onlyOwner {
        certs[cert_hash].exist = false;
        crl[cert_hash] = true;
        crl_map[crl_count] = cert_hash;
        ++crl_count;
    }

    function get_cert(string memory cert_hash)
        private view returns(X509 memory) {
        if (!certs[cert_hash].exist) {
            return NULL;
        } else {
            return certs[cert_hash];
        }
    }

    function verify(string memory cert_hash)
        public view returns(bool) {
        if (msg.sender == get_cert(cert_hash).wallet_owner){
            return true;
        } else {
            return false;
        }
    }

    function get_crl()
        public view returns(X509[] memory) {
        X509[] memory list = new X509[](crl_count);
        for (uint i = 0; i < crl_count; ++i) {
            list[i] = certs[crl_map[i]];
        }
        return list;
    }

    function get_certs()
        public view returns(X509[] memory) {
        X509[] memory list = new X509[](certs_count - crl_count);
        for (uint i = 0; i < certs_count; ++i) {
            if (!crl[certs_map[i]])
                list[i] = certs[certs_map[i]];
        }
        return list;
    }

    function get_all_certs()
        public view returns(X509[] memory) {
        X509[] memory list = new X509[](certs_count);
        for (uint i = 0; i < certs_count; ++i) {
            list[i] = certs[certs_map[i]];
        }
        return list;
    }

}
