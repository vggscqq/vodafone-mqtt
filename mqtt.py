import paho.mqtt.client as mqtt
import json

# MQTT broker details
MQTT_BROKER = "192.168.0.102"
MQTT_PORT = 1883
MQTT_USERNAME = "mqtt-user"
MQTT_PASSWORD = "mqttpassword"
MQTT_TOPIC = "home/devices/status"

# Device list
devices = [
    ["my-laptop", "aa:aa:aa:aa:aa", "wired"],
    ["my-phone", "bb:bb:bb:bb:bb", "wireless"],
]

# Publish devices to MQTT
def publish_devices():
    client = mqtt.Client(protocol=mqtt.MQTTv311)
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.connect(MQTT_BROKER, MQTT_PORT, 60)

    payload = {"devices": [{"name": d[0], "mac": d[1], "type": d[2]} for d in devices]}
    client.publish(MQTT_TOPIC, json.dumps(payload))
    client.disconnect()


if __name__ == "__main__":
    publish_devices()
