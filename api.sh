#!/bin/bash

read -p "enter an IP: " address
curl https://api.db-ip.com/v2/free/$address
echo ' '
