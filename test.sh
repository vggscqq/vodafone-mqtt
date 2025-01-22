#!/bin/bash

# Assuming all devices are disconnected

mosquitto_pub -h 192.168.0.102 -p 1883 -u "mqtt-user" -P "mqttpassword" -t "home/devices/00000000000000000/state" -m disconnecte
