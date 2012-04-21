# Configuration Parameters
MYSQL_PASSWORD="password"
RABBIT_USER="mcollective"
RABBIT_PASSWORD="password"
MCOLLECTIVE_PSK="mcollectivePSKmcollective"
FOREMAN_EMAIL="root@test.local"
DOMAIN="local"

# Initial CentOS system clean-up + upgrades
yum -y erase wireless-tools gtk2 libX11 hicolor-icon-theme avahi freetype bitstream-vera-fonts
yum -y upgrade
yum -y clean all

# Installing vagrant keys
mkdir /home/vagrant/.ssh
chmod 700 /home/vagrant/.ssh
cd /home/vagrant/.ssh
wget --no-check-certificate 'http://github.com/mitchellh/vagrant/raw/master/keys/vagrant.pub' -O authorized_keys
chown -R vagrant /home/vagrant/.ssh

# Installing the virtualbox guest additions
VBOX_VERSION=$(cat /home/vagrant/.vbox_version)
cd /tmp
wget http://download.virtualbox.org/virtualbox/$VBOX_VERSION/VBoxGuestAdditions_$VBOX_VERSION.iso
mount -o loop VBoxGuestAdditions_$VBOX_VERSION.iso /mnt
sh /mnt/VBoxLinuxAdditions.run
umount /mnt
rm VBoxGuestAdditions_$VBOX_VERSION.iso

# Allow sudo commands without a tty
sed -i "s/^.*requiretty/#Defaults requiretty/" /etc/sudoers

# Configure hostname
echo -e "127.0.0.1 puppet.${DOMAIN} puppet foreman.${DOMAIN} foreman localhost" > /etc/hosts
echo -e "NETWORKING=yes\nHOSTNAME=puppet.${DOMAIN}" > /etc/sysconfig/network
hostname puppet.${DOMAIN}

# Puppet Labs repositories ( dependancies, product )
rpm -ivh http://yum.puppetlabs.com/el/6/products/x86_64/puppetlabs-release-6-1.noarch.rpm
# EPEL repository 
rpm -ivh http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-5.noarch.rpm

# Installation of majority of stack packages
yum -y install git
yum -y install rubygems ruby-devel rubygem-stomp
yum -y install httpd httpd-devel mod_ssl
yum -y install mysql mysql-server mysql-devel
yum -y install libxml2 libxml2-devel libxslt libxslt-devel
yum -y install libcurl-devel openssl-devel openssl098e tcl tk unixODBC unixODBC-devel augeas
yum -y install libvirt libvirt-devel

# To keep in line with vagrant standart
gem install --no-rdoc --no-ri chef

# Installation of stack gems
gem install --no-rdoc --no-ri rest-client json mime-types
gem install --no-rdoc --no-ri -v 3.0.10 passenger
gem install --no-rdoc --no-ri stomp  
gem install --no-rdoc --no-ri puppet rack mysql net-ping
gem install --no-rdoc --no-ri -v 3.0.10 rails activerecord
gem install --no-rdoc --no-ri bundle

#Acquire puppet version for later use
PUPPET_VERSION=$(puppet --version)

# Deploy required Puppet user, files, and directories
adduser puppet

mkdir -p /etc/puppet/{manifests,modules}
mkdir -p /usr/share/puppet/rack/puppetmasterd/{public,tmp}

mkdir -p /var/lib/puppet/{bucket,yaml,rrd,server_data,reports}
chown puppet:puppet /var/lib/puppet/{bucket,yaml,rrd,server_data,reports}

cp /usr/lib/ruby/gems/1.8/gems/puppet-${PUPPET_VERSION}/ext/rack/files/config.ru /usr/share/puppet/rack/puppetmasterd/config.ru
chown puppet:puppet /usr/share/puppet/rack/puppetmasterd/config.ru

# Install Foreman
mkdir -p /usr/share/foreman
git clone https://github.com/theforeman/foreman.git -b develop /usr/share/foreman

# mCollective & Plugins
yum -y install mcollective mcollective-common mcollective-client

cd /usr/libexec/mcollective/mcollective/application
for i in filemgr nettest package puppetd service; do
    wget https://raw.github.com/puppetlabs/mcollective-plugins/master/agent/$i/application/$i.rb
done
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/etcfacts/application/etcfacts.rb
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/shellcmd/application/shellcmd.rb
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/yum/application/yum.rb

cd /usr/libexec/mcollective/mcollective/agent
for i in nettest filemgr puppetd puppetral puppetca; do 
    wget https://raw.github.com/puppetlabs/mcollective-plugins/master/agent/$i/agent/$i.rb
    wget https://raw.github.com/puppetlabs/mcollective-plugins/master/agent/$i/agent/$i.ddl
done
 
wget -O package.rb https://raw.github.com/puppetlabs/mcollective-plugins/master/agent/package/agent/puppet-package.rb
wget https://raw.github.com/puppetlabs/mcollective-plugins/master/agent/package/agent/package.ddl
wget -O service.rb https://raw.github.com/puppetlabs/mcollective-plugins/master/agent/service/agent/puppet-service.rb
wget https://raw.github.com/puppetlabs/mcollective-plugins/master/agent/service/agent/service.ddl
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/etcfacts/etc_facts.rb
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/etcfacts/etc_facts.ddl
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/shellcmd/shellcmd.rb
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/shellcmd/shellcmd.ddl
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/yum/yum.rb
wget https://raw.github.com/phobos182/mcollective-plugins/master/agent/yum/yum.ddl

cd /usr/libexec/mcollective/mcollective/facts/
wget https://raw.github.com/puppetlabs/mcollective-plugins/master/facts/facter/facter_facts.rb

# Fix ODBC requirement for Erlang - seems to be not nescessary in 14B
#ln -s /usr/lib64/libodbc.so.2 /usr/lib64/libodbc.so.1

# Install Erlang
yum -y install erlang

# Install RabbitMQ & Plugins
yum -y install rabbitmq-server

RABBITMQ_SERVER_VERSION=`rpm -q --qf '%{VERSION}' rabbitmq-server`
cd /usr/lib/rabbitmq/lib/rabbitmq_server-${RABBITMQ_SERVER_VERSION}/plugins
wget http://www.rabbitmq.com/releases/plugins/v${RABBITMQ_SERVER_VERSION}/amqp_client-${RABBITMQ_SERVER_VERSION}.ez 
wget http://www.rabbitmq.com/releases/plugins/v${RABBITMQ_SERVER_VERSION}/rabbitmq_stomp-${RABBITMQ_SERVER_VERSION}.ez

chkconfig rabbitmq-server on
service rabbitmq-server start

# Configure RabbitMQ user/privileges
rabbitmqctl add_user ${RABBIT_USER} ${RABBIT_PASSWORD}
rabbitmqctl set_permissions ${RABBIT_USER} ".*" ".*" ".*"
rabbitmqctl delete_user guest

# Install Apache Passenger module
passenger-install-apache2-module -a

# Configuration files for mCollective
cat > /etc/mcollective/server.cfg << EOF
topicprefix = /topic/
main_collective = mcollective
collectives = mcollective
libdir = /usr/libexec/mcollective
logfile = /var/log/mcollective.log
loglevel = info
daemonize = 1

securityprovider = psk
plugin.psk = $MCOLLECTIVE_PSK

connector = stomp
plugin.stomp.host = localhost
plugin.stomp.port = 61613
plugin.stomp.user = $RABBIT_USER
plugin.stomp.password = $RABBIT_PASSWORD

factsource = facter
EOF

cat > /etc/mcollective/client.cfg << EOF
topicprefix = /topic/
main_collective = mcollective
collectives = mcollective
libdir = /usr/libexec/mcollective
logfile = /dev/null
loglevel = info

securityprovider = psk
plugin.psk = $MCOLLECTIVE_PSK

connector = stomp
plugin.stomp.host = localhost
plugin.stomp.port = 61613
plugin.stomp.user = $RABBIT_USER
plugin.stomp.password = $RABBIT_PASSWORD

factsource = facter
EOF

# Configure MySQL
chkconfig mysqld on && service mysqld start
mysql -u root -e "CREATE DATABASE puppet;"
mysql -u root -e "GRANT ALL PRIVILEGES ON puppet.* TO puppet@localhost IDENTIFIED BY '${MYSQL_PASSWORD}';"

# Puppet configuration
cat > /etc/puppet/puppet.conf << EOF
[main]
    logdir = /var/log/puppet
    rundir = /var/run/puppet
    ssldir = \$vardir/ssl
    factpath = \$vardir/lib/facter
    templatedir = \$confdir/templates
    pluginsync = true
    classfile = \$vardir/classes.txt
    localconfig = \$vardir/localconfig
    reportdir = /var/lib/puppet/reports

[agent]
  report = true
  ignorecache = true

[master]
    reports = http,store,log,foreman
    ssl_client_header = SSL_CLIENT_S_DN
    ssl_client_verify_header = SSL_CLIENT_VERIFY
    storeconfigs = true
    dbadapter = mysql
    dbuser = puppet
    dbpassword = $MYSQL_PASSWORD
    dbname = puppet
    dbserver = localhost
    dbsocket = /var/lib/mysql/mysql.sock
EOF

# Foreman configuration files
cat > /usr/share/foreman/config/database.yml << EOF
production:
  adapter: mysql
  database: puppet
  username: puppet
  password: $MYSQL_PASSWORD
  host: localhost
  socket: "/var/lib/mysql/mysql.sock"
EOF

cat > /usr/share/foreman/config/settings.yaml << EOF
--- 
:modulepath: /etc/puppet/modules/
:tftppath: tftp/
:ldap: false
:puppet_server: puppet
:unattended: false
:puppet_interval: 30
:document_root: /usr/share/foreman/public
:administrator: $FOREMAN_EMAIL
:foreman_url: foreman.$DOMAIN
EOF

cat > /usr/share/foreman/config/email.yaml << EOF
production:
  delivery_method: :smtp
  smtp_settings:
    address: localhost
    port: 25
    domain: $DOMAIN
    authentication: :none
EOF


# Foreman report for Puppet
# https://raw.github.com/theforeman/puppet-foreman/master/templates/foreman-report.rb.erb
cat > /usr/lib/ruby/gems/1.8/gems/puppet-${PUPPET_VERSION}/lib/puppet/reports/foreman.rb << EOF
\$foreman_url="https://foreman.$DOMAIN:443"

require 'puppet'
require 'net/http'
require 'uri'

Puppet::Reports.register_report(:foreman) do
    Puppet.settings.use(:reporting)
    desc "Sends reports directly to Foreman"

    def process
      begin
        uri = URI.parse(\$foreman_url)
        http = Net::HTTP.new(uri.host, uri.port)
        if uri.scheme == 'https' then
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
        req = Net::HTTP::Post.new("/reports/create?format=yml")
        req.set_form_data({'report' => to_yaml})
        response = http.request(req)
      rescue Exception => e
        raise Puppet::Error, "Could not send report to Foreman at #{\$foreman_url}/reports/create?format=yml: #{e}"
      end
    end
end
EOF

# Apache configuration files
cat > /etc/httpd/conf.d/puppet.conf << EOF
Listen 8140
<VirtualHost *:8140>
    SSLEngine on
    SSLCipherSuite SSLv2:-LOW:-EXPORT:RC4+RSA
    SSLCertificateFile      /var/lib/puppet/ssl/certs/puppet.${DOMAIN}.pem
    SSLCertificateKeyFile   /var/lib/puppet/ssl/private_keys/puppet.${DOMAIN}.pem
    SSLCertificateChainFile /var/lib/puppet/ssl/ca/ca_crt.pem
    SSLCACertificateFile    /var/lib/puppet/ssl/ca/ca_crt.pem
    SSLCARevocationFile     /var/lib/puppet/ssl/ca/ca_crl.pem
    SSLVerifyClient optional
    SSLVerifyDepth  1
    SSLOptions +StdEnvVars

    RackAutoDetect On
    DocumentRoot /usr/share/puppet/rack/puppetmasterd/public/
    <Directory /usr/share/puppet/rack/puppetmasterd/>
        Options None
        AllowOverride None
        Order allow,deny
        allow from all
    </Directory>
</VirtualHost>
EOF

PASSENGER_VERSION=$(passenger-config --version)
cat > /etc/httpd/conf.d/passenger.conf << EOF
LoadModule passenger_module /usr/lib/ruby/gems/1.8/gems/passenger-${PASSENGER_VERSION}/ext/apache2/mod_passenger.so
PassengerRoot /usr/lib/ruby/gems/1.8/gems/passenger-${PASSENGER_VERSION}
PassengerRuby /usr/bin/ruby
EOF

cat > /etc/httpd/conf.d/foreman.conf << EOF
Listen 443
NameVirtualHost *:443
LoadModule ssl_module modules/mod_ssl.so
AddType application/x-x509-ca-cert .crt
AddType application/x-pkcs7-crl .crl

<VirtualHost *:443>  
    ServerName foreman.${DOMAIN}

    RailsAutoDetect On
    DocumentRoot /usr/share/foreman/public

    <Directory /usr/share/foreman/public>
        Options FollowSymLinks
        DirectoryIndex index.html
        AllowOverride None
        Order allow,deny
        allow from all
    </Directory>

    SSLEngine On
    SSLCertificateFile      /var/lib/puppet/ssl/certs/puppet.${DOMAIN}.pem
    SSLCertificateKeyFile   /var/lib/puppet/ssl/private_keys/puppet.${DOMAIN}.pem
</VirtualHost>
EOF

# Remove stock Apache configuration files
rm -f /etc/httpd/conf.d/ssl.conf
rm -f /etc/httpd/conf.d/welcome.conf

# IPTables configuration
cat > /etc/sysconfig/iptables << "EOF"
# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 8140 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 61613 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF

# Enable IPTables ruleset
service iptables restart

# Set Foreman symlinks 
mkdir -p /etc/foreman
ln -sf /usr/share/foreman/config/database.yml /etc/foreman/database.yml
ln -sf /usr/share/foreman/config/settings.yaml /etc/foreman/settings.yaml
ln -sf /usr/share/foreman/config/email.yaml /etc/foreman/email.yaml

# Enable mCollective
chkconfig mcollective on
service mcollective start

# Generate Puppet master CA
puppet cert --generate puppet.${DOMAIN} 

# Rake Foreman
cd /usr/share/foreman
bundle install --path vendor/cache --without postgresql development
RAILS_ENV=production rake db:migrate

# Enable Apache
chkconfig httpd on
service httpd start

# Work around
# http://projects.reductivelabs.com/issues/2244
mkdir -p /etc/puppet/modules/dummy_module/lib

# Execute Puppet agent
puppet agent -t

# Finished
exit
