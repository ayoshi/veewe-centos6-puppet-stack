### Report Cleanup - foreman , puppet , rabbitmq
### monit passenger, rabbitmq
### Make foreman work as ENC

# Configuration Parameters
MYSQL_PASSWORD="password"
RABBIT_USER="mcollective"
RABBIT_PASSWORD="password"
MCOLLECTIVE_PSK="mcollectivePSKmcollective"
FOREMAN_EMAIL="root@test.local"
DOMAIN="local"

date > /etc/vagrant_box_build_time

# Disable SELinux
setenforce permissive

# For minimal Centos 6.2 CD
yum -y install gcc make gcc-c++ ruby kernel-devel-`uname -r` zlib-devel \
       openssl-devel readline-devel sqlite-devel perl git wget
yum -y upgrade

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
echo -e "NETWORKING=yes\nHOSTNAME=puppet" > /etc/sysconfig/network
hostname puppet

# Puppet Labs repositories ( dependancies, product )
rpm -ivh http://yum.puppetlabs.com/el/6/products/x86_64/puppetlabs-release-6-1.noarch.rpm
# EPEL repository 
rpm -ivh http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-5.noarch.rpm
# Foreman repo
rpm -ivh http://yum.theforeman.org/stable/RPMS/foreman-release-1-1.noarch.rpm

# Installation of majority of stack packages
yum -y install rubygems ruby-devel rubygem-stomp ruby-mysql rubygem-rack
yum -y install httpd httpd-devel mod_ssl
yum -y install mysql mysql-server mysql-devel
yum -y install libxml2 libxml2-devel libxslt libxslt-devel
yum -y install libcurl-devel openssl-devel openssl098e tcl tk unixODBC unixODBC-devel augeas
yum -y install libvirt libvirt-devel 

yum -y install puppet
# To keep in line with vagrant standart
gem install --no-rdoc --no-ri chef

# Installation of stack gems
gem install --no-rdoc --no-ri -v 3.0.10 passenger
gem install --no-rdoc --no-ri -v 3.0.10 rails activerecord
gem install --no-rdoc --no-ri bundle

#Acquire puppet version for later use
PUPPET_VERSION=$(puppet --version)

# Install Foreman
yum -y install foreman

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

# Configure puppet as rack application
mkdir -p /etc/puppet/rack/{public,tmp}
cp /usr/share/puppet/ext/rack/files/config.ru /etc/puppet/rack/config.ru
chown puppet:puppet /etc/puppet/rack/config.ru


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
cat > /etc/foreman/database.yml << EOF
production:
  adapter: mysql
  database: puppet
  username: puppet
  password: $MYSQL_PASSWORD
  host: localhost
  socket: "/var/lib/mysql/mysql.sock"
EOF

cat > /etc/foreman/settings.yaml << EOF
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

cat > /etc/foreman/email.yaml << EOF
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
#cat > /usr/lib/ruby/gems/1.8/gems/puppet-${PUPPET_VERSION}/lib/puppet/reports/foreman.rb << EOF
cat > /usr/lib/ruby/site_ruby/1.8/puppet/reports/foreman.rb << EOF

# copy this file to your report dir - e.g. /usr/lib/ruby/1.8/puppet/reports/
# add this report in your puppetmaster reports - e.g, in your puppet.conf add:
# reports=log, foreman # (or any other reports you want)

# URL of your Foreman installation
\$foreman_url="https://foreman.$DOMAIN:443"

require 'puppet'
require 'net/http'
require 'net/https'
require 'uri'

Puppet::Reports.register_report(:foreman) do
    Puppet.settings.use(:reporting)
    desc "Sends reports directly to Foreman"

    def process
      begin
        uri = URI.parse($foreman_url)
        http = Net::HTTP.new(uri.host, uri.port)
        if uri.scheme == 'https' then
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
        req = Net::HTTP::Post.new("#{uri.path}/reports/create?format=yml")
        req.set_form_data({'report' => to_yaml})
        response = http.request(req)
      rescue Exception => e
        raise Puppet::Error, "Could not send report to Foreman at #{$foreman_url}/reports/create?format=yml: #{e}"
      end
    end
end

EOF

# Apache configuration files
cat > /etc/httpd/conf.d/puppet.conf << EOF

PassengerHighPerformance on
PassengerMaxPoolSize 12
PassengerPoolIdleTime 1500
# PassengerMaxRequests 1000
PassengerStatThrottleRate 120
RackAutoDetect Off
RailsAutoDetect Off

<VirtualHost *:8140>
    SSLEngine on
    SSLProtocol -ALL +SSLv3 +TLSv1
    SSLCipherSuite ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:-LOW:-SSLv2:-EXP

    SSLCertificateFile      /var/lib/puppet/ssl/certs/puppet.${DOMAIN}.pem
    SSLCertificateKeyFile   /var/lib/puppet/ssl/private_keys/puppet.${DOMAIN}.pem
    SSLCertificateChainFile /var/lib/puppet/ssl/ca/ca_crt.pem
    SSLCACertificateFile    /var/lib/puppet/ssl/ca/ca_crt.pem
    SSLCARevocationFile     /var/lib/puppet/ssl/ca/ca_crl.pem

    SSLVerifyClient optional
    SSLVerifyDepth  1
    SSLOptions +StdEnvVars

    RequestHeader set X-SSL-Subject %{SSL_CLIENT_S_DN}e
    RequestHeader set X-Client-DN %{SSL_CLIENT_S_DN}e
    RequestHeader set X-Client-Verify %{SSL_CLIENT_VERIFY}e

    DocumentRoot /etc/puppet/rack/public/
    RackBaseURI /
    RackAutoDetect On
    <Directory /etc/puppet/rack/>
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

# Enable mCollective
chkconfig mcollective on
service mcollective start

# Generate Puppet master CA
find $(puppet master --configprint ssldir) -name $(puppet master --configprint certname) -delete
#puppet cert --generate puppet.${DOMAIN} --dns_alt_names=puppet 
puppet cert --generate puppet.${DOMAIN} 

# Rake Foreman
cd /usr/share/foreman
RAILS_ENV=production rake db:migrate

# Work around http://projects.reductivelabs.com/issues/2244
mkdir -p /etc/puppet/modules/dummy_module/lib
# Needed too it seems
mkdir -p /etc/puppet/manifests

# Enable Apache
chkconfig httpd on
service httpd start


# Execute Puppet agent
puppet agent -t

#Clean-up
yum -y clean all
dd if=/dev/zero of=/tmp/clean || rm /tmp/clean

# Finished
exit
