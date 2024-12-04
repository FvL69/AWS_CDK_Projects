#!/bin/bash

# Update the system
sudo dnf update -y

# Install Apache web server
sudo dnf install -y httpd

# Create a simple web page
echo "<h1>Hello World from $(hostname -f)</h1>" > /var/www/html/index.html

# Set appropriate permissions
sudo chown -R ec2-user:apache /var/www/html
sudo chmod -R 755 /var/www/html

# Start and enable Apache
sudo systemctl start httpd
sudo systemctl enable httpd
