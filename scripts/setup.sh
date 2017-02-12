#!/usr/bin/env bash
# Update the apt repo and install the necessary packages:
# - unzip : unpackage DROID download
sudo apt-get update
sudo apt-get install -y unzip openjdk-7-jre

# Dump the downloads in /tmp, download the software packages
# - DROID v6.3 binary
cd /tmp
wget http://www.nationalarchives.gov.uk/documents/information-management/droid-binary-6.3-bin.zip

# Create at user lib dir for droid and unpackage and set up
sudo mkdir /usr/local/lib/tna-droid
cd /usr/local/lib/tna-droid
sudo unzip /tmp/droid-binary-6.3-bin.zip
sudo chmod +x droid.sh
sudo ln -s /usr/local/lib/tna-droid/droid.sh /usr/local/bin/droid
sudo wget http://www.nationalarchives.gov.uk/documents/DROID_SignatureFile_V88.xml

# Create the handy application works for Apache Tika
sudo mkdir /usr/local/lib/apache-tika
cd /usr/local/lib/apache-tika
sudo wget http://mirror.ox.ac.uk/sites/rsync.apache.org/tika/tika-app-1.14.jar
sudo cp /vagrant/scripts/tika.sh ./
sudo chmod +x tika.sh
sudo ln -s /usr/local/lib/apache-tika/tika.sh /usr/local/bin/tika
