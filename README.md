# ATT&amp;CLI
An offline, CLI-based MITRE ATT&amp;CK Matrix browser. Written in Rust.

## Authors
- @XoanOuteiro

## Installation
Installing the app will create the ~/.mitre/ folder and download to it a 42mb JSON file containing the MITRE ATT&CK Matrix.
The compiled rust binary will be automatically added to the path.

Simply run:

``` bash
git clone https://github.com/Teixuguinho-Craftsmanship/ATT-CLI
chmod +x install.sh && ./install.sh
```

You will need to have cargo installed in your system

 ## Usage:

Listing all APTs:

``` bash
attcli apt-list
```

Seeing details on an APT (name, info, techniques used):

``` bash
attcli apt (id or name)
```

Seeing details on a technique:

``` bash
attcli tid (technique id)
attcli tn (technique name)
```

Seeing all tactics:

``` bash
attcli tactic
```

Seeing a tactic (info and related techniques):

``` bash
attclic tactic (id or name)
```
