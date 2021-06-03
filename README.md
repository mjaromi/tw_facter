# tw_facter
Facter for BMC Discovery

# Description

`tw_facter` is a tool which provides facts about BMC Discovery Appliance in JSON format.

`tw_facter` can provide following information:

| kind        | description           |
|:-------------:|:-------------:|
| appliance     | info about BMC Discovery appliance |
| cluster       | info about cluster service |
| custom        | custom facts defined in ~/.tw_facter_custom |
| cores         | info about cores files |
| discovery     | info about discovery like exclude ranges, scheduled runs or processing runs |
| env           | env variables |
| facter        | info about tw_facter |
| jdbc          | info about jdbc |
| metadata      | some metadata |
| omninames     | info about omninames service |
| options       | tw_options |
| rpms          | info about rpms |
| security      | tw_secopts |
| services      | tw_service_control |
| system        | info about OS |
| taxonomy      | info about taxonomy |
| users         | info about users |
| vault         | info about credentials |
| windows       | info about windows, pools and proxies |

# Requirements
* by default it does expect `tw_facter` user with `Public, System` permissions and password file in `/usr/tideway/.tw_facter_passwd`
* other (not mandatory, but highly recommended) tool -> see below

# Installation
```bash
mkdir -p /usr/tideway/bin-custom/
wget https://raw.githubusercontent.com/mjaromi/tw_facter/master/tw_facter.py -O /usr/tideway/bin-custom/tw_facter.py
chmod +x /usr/tideway/bin-custom/tw_facter.py
ln -s /usr/tideway/bin-custom/tw_facter /usr/tideway/bin/tw_facter
```

# Create tw_facter user
```bash
tw_facter_passwd_file=/usr/tideway/.tw_facter_passwd
tw_facter_passwd=$(openssl rand -base64 12 | tee ${tw_facter_passwd_file})
tw_adduser --fullname=tw_facter --groups=public,system --password=${tw_facter_passwd} --no-force-password-change tw_facter
chmod 644 ${tw_facter_passwd_file}
chown tideway.tideway ${tw_facter_passwd_file}
```

# Other tools
## jq - command-line JSON processor
```bash
wget -q https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -O /usr/tideway/bin-custom/jq
chmod +x /usr/tideway/bin-custom/jq
ln -s /usr/tideway/bin-custom/jq /usr/tideway/bin/jq
```

# Usage
## Syntax
By default you can run it just like this and it will provide all kinds mentioned above.
```bash
tw_facter
```

Show `tw_facter` version:
```bash
tw_facter -v 
```

Dry run:
```bash
tw_facter -d
```

Dry run with some kinds:
```bash
tw_facter -d -k services appliance discovery
```

# Examples
### show services
```bash
tw_facter | jq '.services'
```
or
```bash
tw_facter -d -k services | jq
```

### show custom facts
```bash
tw_facter | jq '.custom'
```
or
```bash
tw_facter -d -k custom | jq
```

### show username + user_state
```bash
tw_facter | jq -r '.users | with_entries(.value |= .user.state)'
```
or
```bash
tw_facter -d -k users | jq -r '.users | to_entries[] | "\(.key) - \(.value | .user.state)"'
```

### show username + fullname + user_state
```bash
tw_facter | jq -r '.users | to_entries[] | "\(.key), \(.value | .fullname), \(.value | .user.state)"'
```
or
```bash
tw_facter -d -k users | jq -r '.users | to_entries[] | "\(.key), \(.value | .fullname), \(.value | .user.state)"'
```

### show vault
```bash
tw_facter | jq '.vault'
```
or
```bash
tw_facter -d -k vault | jq
```

### show vault credentials, types == sql
```bash
tw_facter | jq '.vault[] | select(.types[] == "sql")'
```
or
```bash
tw_facter -d -k vault | jq '.vault[] | select(.types[] == "sql")'
```
