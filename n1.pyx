import enc

def debug(str message):
    print ("debug: %s" % message)

def main():
    debug("Entered main().")

    keys = enc.generate_RSA(4096)
    
    debug("Private Key=[%s], Public Key=[%s]." % (str(keys[0]),  str(keys[1])))

    id = enc.generate_ID(keys[1])

    debug("id=[%s]." % id.hexdigest())

main()
