import enc

def debug(message):
    print ("debug: %s" % message)

def main():
    debug("Entered main().")

    private_key = enc.generate_RSA(4096)
    public_key = private_key.publickey();
    
    debug("Private Key=[%s], Public Key=[%s]." % (str(private_key.exportKey("PEM")),  str(public_key.exportKey("PEM"))))

    id = enc.generate_ID(public_key.exportKey("DER"))

    debug("id=[%s]." % id.hexdigest())

main()
