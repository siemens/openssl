#! /bin/bash
set -e
mkcert_sh="/home/rajeevranjan/git/CMP/openssl/test/certs/mkcert.sh"
# This script generates the certificates needed for the CMP server and the signer

server_rootCA_KeyAlg="MLDSA65"
server_leaf_KeyAlg="SLH-DSA-SHAKE-192s"

signer_rootCA_KeyAlg="MLDSA65"
signer_interCA_KeyAlg="MLDSA65"
signer_subinterCA_KeyAlg="MLDSA65"
signer_leaf_KeyAlg="MLDSA65"


# CMP server certificate
rename_serverfiles() {
    echo "Renaming server files"
    rm server_root-key.pem
    mv server_root-cert.pem server_root.crt
    cp server_root.crt trusted.crt
    mv server-key.pem server.key
    mv server-cert.pem server.crt
}
remove_serverfiles() {
    echo "Removing server files"
    rm -f server.key server-crt trusted.crt server_root.crt
}

gen_servercert() {
    remove_serverfiles
    sleep 5
    OPENSSL_KEYALG=${server_rootCA_KeyAlg} \
    $mkcert_sh genroot "Root CA" server_root-key server_root-cert
    OPENSSL_KEYALG=${server_leaf_KeyAlg} \
    $mkcert_sh genee -p serverAuth,cmKGA server.example server-key server-cert server_root-key server_root-cert
    rename_serverfiles
}

gen_demoCAfolder() {
    echo "Generating demoCA folder"
    mkdir -p demoCA
    touch demoCA/index.txt
    echo 1007 > demoCA/crlnumber
}
rename_signerfiles() {
    echo "Renaming signer files"
    mv signer_root-cert.pem root.crt
    cp root.crt signer_root.crt
    #rm -f signer_root-key.pem signer_interCA-key.pem signer_interCA-cert.pem \
    #    signer_subinterCA-key.pem signer_subinterCA-cert.pem
    mv signer_subinterCA-crl.pem newcrl.pem
    mv signer_leaf-key.pem new.key
    cp new.key signer.key
    mv signer_leaf-cert.pem signer_only.crt
    mv signer_issuing-cert.pem signer_issuing.crt
    mv signer_chain.pem signer.crt
}
remove_signerfiles() {
    echo "Removing signer files"
    rm -f root.crt signer_root.crt newcrl.pem new.key signer.key signer_only.crt \
        signer_issuing.crt signer.crt
}

genee_kem() {
    echo "Generating KEM certificate"
    openssl genpkey -algorithm "$OPENSSL_KEYALG" -out signer_leaf-key.pem -outpubkey signer_leaf-pubkey.pem
    openssl x509 -new -subj "/CN=signer-leaf" -CA signer_subinterCA-cert.pem -CAkey signer_subinterCA-key.pem \
        -out signer_leaf-cert.pem -force_pubkey signer_leaf-pubkey.pem -extensions SAN \
        -extfile <(printf "[SAN]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,keyEncipherment")
}
genee_kem1() {
    local OPTIND=1
    local purpose=serverAuth
    local ku=

    while getopts p:k: o
    do
        case $o in
        p) purpose="$OPTARG";;
        k) ku="keyUsage = $OPTARG";;
        *) echo "Usage: $0 genee [-k KU] [-p EKU] cn keyname certname cakeyname cacertname" >&2
           return 1;;
        esac
    done

    shift $((OPTIND - 1))
    local cn=$1; shift
    local key=$1; shift
    local cert=$1; shift
    local cakey=$1; shift
    local ca=$1; shift

    exts=$(printf "%s\n%s\n%s\n%s\n%s\n[alts]\n%s\n" \
	    "subjectKeyIdentifier = hash" \
	    "authorityKeyIdentifier = keyid, issuer" \
	    "basicConstraints = CA:false" \
            "$ku" \
	    "extendedKeyUsage = $purpose" \
	    "subjectAltName = @alts" "DNS=${cn}")
    csr=$(req "$key" "CN = $cn") || return 1
    echo "$csr" |
	cert "$cert" "$exts" -CA "${ca}.pem" -CAkey "${cakey}.pem" \
	    -set_serial 2 -days "${DAYS}" "$@"
}

gen_signercert() {
    echo "Generating signer certificates"
    remove_signerfiles
    sleep 5
    OPENSSL_KEYALG=${signer_rootCA_KeyAlg} \
    $mkcert_sh genroot "signer-rootCA" signer_root-key signer_root-cert
    OPENSSL_KEYALG=${signer_interCA_KeyAlg} \
    $mkcert_sh genca "signer-interCA" signer_interCA-key signer_interCA-cert signer_root-key signer_root-cert
    OPENSSL_KEYALG=${signer_subinterCA_KeyAlg} \
    $mkcert_sh genca "signer-subinterCA" signer_subinterCA-key signer_subinterCA-cert signer_interCA-key signer_interCA-cert

    OPENSSL_KEYALG=${signer_leaf_KeyAlg}
    if [[ "$signer_leaf_KeyAlg" == *"MLKEM"* ]]; then
        OPENSSL_KEYALG=${signer_leaf_KeyAlg} genee_kem
    else
        OPENSSL_KEYALG=${signer_leaf_KeyAlg} \
        $mkcert_sh genee -p clientAuth "signer-leaf" signer_leaf-key signer_leaf-cert signer_subinterCA-key signer_subinterCA-cert
    fi

    gen_demoCAfolder
    openssl ca -gencrl -keyfile signer_subinterCA-key.pem -cert signer_subinterCA-cert.pem -out signer_subinterCA-crl.pem -crldays 36525 \
            -config <(printf "[ca]\ndefault_ca= CA_default\n[CA_default]\n%s\n%s\n%s\n" \
		      "database = ./demoCA/index.txt" "crlnumber = ./demoCA/crlnumber" "default_md = default")
    cat signer_leaf-cert.pem signer_subinterCA-cert.pem signer_interCA-cert.pem > signer_chain.pem
    cat signer_subinterCA-cert.pem signer_interCA-cert.pem signer_root-cert.pem > signer_fullchain.pem
    openssl pkcs12 -export -out signer.p12 -inkey signer_leaf-key.pem -in signer_leaf-cert.pem -certfile signer_fullchain.pem -password pass:12345
    rm -f signer_fullchain.pem
    cat signer_subinterCA-cert.pem signer_interCA-cert.pem > signer_issuing-cert.pem
    rename_signerfiles
}

all() {
    gen_servercert
    gen_signercert
}

"$@"
