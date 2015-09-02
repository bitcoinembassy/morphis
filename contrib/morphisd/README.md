# morphisd

Have MORPHiS run as a service under systemd.

## Contents
.
├── etc
│   └── default
│       └── morphisd
├── opt
│   └── morphis
│       ├── morphisd
│       └── setargv
└── usr
    └── lib
        └── systemd
            └── system
                └── morphisd.service

## Install

This setup assumes that MORPHiS is installed in `/opt/morphis` and
will run as the user `morphis` (you can change this in the file
`morphisd.service`).

Copy the files above to the locations shown, then do

    # systemctl daemon-reload
    # systemctl start morphisd.service

If you want MORPHiS to start at reboot, do

    # systemctl enable morphisd.service

## License

GPL v3+

## Bugs

If you find any bugs, or have suggestions, please send me a Dmail:

    ksn3r6aw8ou6s6nq41xk51g9rktrcanz

// Klaus Alexander Seistrup
