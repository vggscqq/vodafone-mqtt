import binascii
import hashlib
import json
import re
import requests
from Crypto.Cipher import AES
import paho.mqtt.client as mqtt
import yaml
from pathlib import Path
import time

SLEEP_TIMEOUT = 10

def load_config():
    try:
        config_path = Path('config.yml')
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            
        # Create variables from config
        ROUTER_IP = config['router']['ip']
        ROUTER_PASSWORD = config['router']['password']
        
        MQTT_BROKER = config['mqtt']['broker']
        MQTT_PORT = config['mqtt']['port']
        MQTT_USERNAME = config['mqtt']['username']
        MQTT_PASSWORD = config['mqtt']['password']
        MQTT_TOPIC_DEV = config['mqtt']['topic_dev']
        MQTT_TOPIC_DEVS = config['mqtt']['topic_devs']
            
        return {
            'ROUTER_IP': ROUTER_IP,
            'ROUTER_PASSWORD': ROUTER_PASSWORD,
            'MQTT_BROKER': MQTT_BROKER,
            'MQTT_PORT': MQTT_PORT,
            'MQTT_USERNAME': MQTT_USERNAME,
            'MQTT_PASSWORD': MQTT_PASSWORD,
            'MQTT_TOPIC_DEV': MQTT_TOPIC_DEV,
            'MQTT_TOPIC_DEVS': MQTT_TOPIC_DEVS
        }
    except FileNotFoundError:
        raise FileNotFoundError("config.yml file not found")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing config.yml: {str(e)}")
    except KeyError as e:
        raise KeyError(f"Missing required configuration key: {str(e)}")

class Router:
    def __init__(self, address, key, timeout=10):
        self.ip_address = address
        self.url = f"http://{address}"
        self.username = "admin"
        self.password = key
        self.timeout = timeout
        self.session = requests.Session()

    def login(self):
        try:
            r = self.session.get(self.url, timeout=self.timeout)
            r.raise_for_status()

            current_session_id = re.search(r"var currentSessionId = '(.+)';", r.text)[1]
            iv = re.search(r"var myIv = '(.+)';", r.text)[1]
            salt = re.search(r"var mySalt = '(.+)';", r.text)[1]

            key = hashlib.pbkdf2_hmac(
                "sha256", self.password.encode(), binascii.unhexlify(salt), 1000, 16
            )
            secret = {"Password": self.password, "Nonce": current_session_id}
            plaintext = json.dumps(secret).encode()
            cipher = AES.new(key, AES.MODE_CCM, binascii.unhexlify(iv))
            cipher.update("loginPassword".encode())
            encrypted_data = cipher.encrypt(plaintext) + cipher.digest()

            login_data = {
                "EncryptData": binascii.hexlify(encrypted_data).decode(),
                "Name": self.username,
                "AuthData": "loginPassword",
            }

            r = self.session.post(
                f"{self.url}/php/ajaxSet_Password.php",
                headers={"Content-Type": "application/json"},
                data=json.dumps(login_data),
                timeout=self.timeout,
            )
            r.raise_for_status()

            if "AdminMatch" not in r.text:
                raise Exception("Login failed")

            result = json.loads(r.text)
            csrf_nonce = AES.new(key, AES.MODE_CCM, binascii.unhexlify(iv)).decrypt(
                binascii.unhexlify(result["encryptData"])
            )[:32]
            self.session.headers.update(
                {
                    "X-Requested-With": "XMLHttpRequest",
                    "csrfNonce": csrf_nonce.decode(),
                    "Origin": f"{self.url}/",
                }
            )
        except Exception as e:
            print(f"Login error: {e}")
            return False
        return True

    def get_devices(self):
        try:
            r = self.session.get(f"{self.url}/php/overview_data.php", timeout=self.timeout)
            r.raise_for_status()
            raw_html = r.text

            lan_devices = json.loads(re.search(r"json_lanAttachedDevice = (.+);", raw_html)[1])
            wlan_devices = json.loads(
                re.search(r"json_primaryWlanAttachedDevice = (.+);", raw_html)[1]
            )
            return lan_devices, wlan_devices
        except Exception as e:
            print(f"Error fetching device data: {e}")
            print(f"Sleeping for {SLEEP_TIMEOUT*2}seconds...")
            time.sleep(SLEEP_TIMEOUT*2)
            return [], []

    def logout(self):
        try:
            self.session.post(f"{self.url}/php/logout.php", timeout=self.timeout)
        except Exception as e:
            print(f"Logout error: {e}")


def return_devices(lan_devices, wlan_devices):
    devices = []
    #print("LAN Devices:")
    for device in lan_devices:
        print(
            f"\tHostname: {device['HostName']}, MAC: {device['MAC']}, IPv4: {device['IPv4']}"
        )
        devices.append([device['HostName'], device['MAC'], "wired"])
        devices.append(device['MAC'])
    

    #print("\nWi-Fi Devices:")
    for device in wlan_devices:
        print(
            f"\tHostname: {device['HostName']}, MAC: {device['MAC']}, IPv4: {device['IPv4']}"
        )
        devices.append([device['HostName'], device['MAC'], "wireless"])
        devices.append(device['MAC'])
    
    return devices

def return_macs(lan_devices, wlan_devices):
    devices = []
    #print("LAN Devices:")
    for device in lan_devices:
        print(
            f"\tHostname: {device['HostName']}, MAC: {device['MAC']}, IPv4: {device['IPv4']}"
        )
        #devices.append([device['HostName'], device['MAC'], "wired"])
        devices.append(device['MAC'])
    

    #print("\nWi-Fi Devices:")
    for device in wlan_devices:
        print(
            f"\tHostname: {device['HostName']}, MAC: {device['MAC']}, IPv4: {device['IPv4']}"
        )
        #devices.append([device['HostName'], device['MAC'], "wireless"])
        devices.append(device['MAC'])
    
    return devices

# Publish devices to MQTT
def publish_devices(MQTT_BROKER, MQTT_PORT, MQTT_USERNAME, MQTT_PASSWORD, MQTT_TOPIC, devices):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.connect(MQTT_BROKER, MQTT_PORT, 60)

    #print(devices)

    #payload = [d for d in devices]

    #From a list make a string with each element on a new line
    payload = " ".join(devices)

    #payload = {"devices": [{"name": d[0], "mac": d[1], "type": d[2]} for d in devices]}
    #print("\n", payload)

    print(f"Published {len(devices)} devices.")

    client.publish(MQTT_TOPIC, json.dumps(payload))
    client.disconnect()


def publish_state(MQTT_USERNAME, MQTT_PASSWORD, MQTT_BROKER, MQTT_PORT, MQTT_TOPIC_DEV, device_mac, state):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.connect(MQTT_BROKER, MQTT_PORT, 60)

    topic = f"{MQTT_TOPIC_DEV}/{device_mac}/state"
    client.publish(topic, state)
    print(f"Published {state} for {device_mac} to {topic}")

if __name__ == "__main__":

    config = load_config()
    router = Router(config['ROUTER_IP'], config['ROUTER_PASSWORD'])
    old_devices = []

    try:
        while True:
            router = Router(config['ROUTER_IP'], config['ROUTER_PASSWORD'])
            if router.login():
                lan_devices, wlan_devices = router.get_devices() 
                new_devices = return_macs(lan_devices, wlan_devices)
                router.logout()

                print("\nScan statistics:")
                print(f"\tNew devices: ", len(new_devices))
                print(f"\tOld devices: ", len(old_devices))
                print("\n\tConnected devices:")
                #for i in new_devices:
                #    print(f"\t\t{i}")

                # Publish device list to MQTT_TOPIC_DEVS
                publish_devices(config['MQTT_BROKER'], config['MQTT_PORT'], config['MQTT_USERNAME'], config['MQTT_PASSWORD'], config['MQTT_TOPIC_DEVS'], new_devices)    

                # Find newly connected devices
                if old_devices == []:
                    if not new_devices == []:
                        print("Initial device scan completed.")
                    else:
                        print("Initial device scan failed. Will try in 30 seconds...")
                    old_devices = new_devices
                    print(f"Sleeping for {SLEEP_TIMEOUT} seconds...\n")
                    time.sleep(SLEEP_TIMEOUT)
                    continue

                connected = set(new_devices) - set(old_devices)
                if connected:
                    for device in connected:
                        print(f"Device connected: {device}")
                        publish_state(config['MQTT_USERNAME'], config['MQTT_PASSWORD'], config['MQTT_BROKER'], config['MQTT_PORT'], config['MQTT_TOPIC_DEV'], device, "connected")

                # Find disconnected devices  
                disconnected = set(old_devices) - set(new_devices)
                if disconnected:
                    for device in disconnected:
                        print(f"Device disconnected: {device}")
                        publish_state(config['MQTT_USERNAME'], config['MQTT_PASSWORD'], config['MQTT_BROKER'], config['MQTT_PORT'], config['MQTT_TOPIC_DEV'], device, "disconnected")

                old_devices = new_devices
                router.logout()  

            print(f"Sleeping for {SLEEP_TIMEOUT}seconds...\n")
            time.sleep(SLEEP_TIMEOUT)
    except KeyboardInterrupt:
        print("Interrupted, logging out.")
        router.logout()

    #if router.login():
    #    lan_devices, wlan_devices = router.get_devices()
    #    devices = return_devices(lan_devices, wlan_devices)
    #    router.logout()
    #    #publish_devices(config['MQTT_BROKER'], config['MQTT_PORT'], config['MQTT_USERNAME'], config['MQTT_PASSWORD'], config['MQTT_TOPIC'], devices)

