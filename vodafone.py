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
import signal
from prettytable import PrettyTable

SLEEP_TIMEOUT = 10

def load_config():
    try:
        config_path = Path('config.yml')
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        
        # Load MQTT config
        MQTT_BROKER = config['mqtt']['broker']
        MQTT_PORT = config['mqtt']['port']
        MQTT_USERNAME = config['mqtt']['username']
        MQTT_PASSWORD = config['mqtt']['password']
        MQTT_TOPIC_DEV = config['mqtt']['topic_dev']
        MQTT_TOPIC_DEVS = config['mqtt']['topic_devs']
        MQTT_TOPIC_DLOI = config['mqtt']['topic_dloi']
        
        # Load DLOIs
        MQTT_DLOIS = {}
        for dloi in config['dloi']:
            MQTT_DLOIS[dloi] = config['dloi'][dloi]['macs']
        
        return {
            'ROUTER_IP': config['router']['ip'],
            'ROUTER_PASSWORD': config['router']['password'],
            'MQTT_BROKER': MQTT_BROKER,
            'MQTT_PORT': MQTT_PORT,
            'MQTT_USERNAME': MQTT_USERNAME,
            'MQTT_PASSWORD': MQTT_PASSWORD,
            'MQTT_TOPIC_DEV': MQTT_TOPIC_DEV,
            'MQTT_TOPIC_DEVS': MQTT_TOPIC_DEVS,
            'MQTT_TOPIC_DLOI': MQTT_TOPIC_DLOI,
            'MQTT_DLOIS': MQTT_DLOIS,
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
        except Exception:
            if r.status_code == 400:
                print("400 error, sleeping for 15 minutes...")
                print("Either someone is logged in or old session is still active.")
                time.sleep(60*15)

            return [], []

    def logout(self):
        try:
            self.session.post(f"{self.url}/php/logout.php", timeout=self.timeout)
        except Exception as e:
            print(f"Logout error: {e}")

# Signal handler for graceful shutdown
def handle_sigterm(signum, frame):
    global keep_running
    print("Received SIGTERM, shutting down gracefully...")
    keep_running = False

def return_macs(lan_devices, wlan_devices):
    devices = []
    for device in lan_devices + wlan_devices:
        devices.append(device['MAC'])
    return devices

def publish_devices(client, topic, devices):
    payload = " ".join(devices)
    client.publish(topic, json.dumps(payload))
    print(f"Published {len(devices)} devices to {topic}.")

def publish_state(client, topic_base, device_mac, state):
    topic = f"{topic_base}/{device_mac}/state"
    client.publish(topic, state)
    print(f"Published {state} for {device_mac} to {topic}")

def publish_dloi_state(client, topic_base, dloi_name, state):
    topic = f"{topic_base}/{dloi_name}"
    client.publish(topic, state)
    print(f"Published DLOI state {state} for {dloi_name} to {topic}")

def print_pretty_device_table(lan_devices, wlan_devices):
    # Print connected devices in a pretty table

    # LAN Devices Table
    lan_table = PrettyTable()
    lan_table.field_names = ["HostName", "MAC", "IPv4"]
    for device in lan_devices:
        lan_table.add_row([device['HostName'], device['MAC'], device['IPv4']])

    print("LAN Devices:")
    print(lan_table)
    print()
    # WLAN Devices Table
    wlan_table = PrettyTable()
    wlan_table.field_names = ["HostName", "MAC", "IPv4"]
    for device in wlan_devices:
        wlan_table.add_row([device['HostName'], device['MAC'], device['IPv4']])

    print("WLAN Devices:")
    print(wlan_table)
    print()

# Global flag to indicate whether the program should keep running
keep_running = True

# Register the signal handler
signal.signal(signal.SIGTERM, handle_sigterm)

if __name__ == "__main__":
    config = load_config()
    router = Router(config['ROUTER_IP'], config['ROUTER_PASSWORD'])
    old_devices = []

    try:
        client = mqtt.Client()
        client.username_pw_set(config['MQTT_USERNAME'], config['MQTT_PASSWORD'])
        client.connect(config['MQTT_BROKER'], config['MQTT_PORT'], 60)
            
        while keep_running:
            if router.login():
                lan_devices, wlan_devices = router.get_devices()
                new_devices = return_macs(lan_devices, wlan_devices)
                router.logout()

                print(f"Scan finished!\nFound {len(lan_devices)} LAN and {len(wlan_devices)} WLAN devices.")
                print_pretty_device_table(lan_devices, wlan_devices)

                if old_devices:
                    connected = set(new_devices) - set(old_devices)
                    disconnected = set(old_devices) - set(new_devices)
                    
                    for device in connected:
                        publish_state(client, config['MQTT_TOPIC_DEV'], device, "connected")
                    for device in disconnected:
                        publish_state(client, config['MQTT_TOPIC_DEV'], device, "disconnected")
                
                old_devices = new_devices

                # Check DLOI states
                for dloi_name, dloi_macs in config['MQTT_DLOIS'].items():
                    dloi_present = bool(set(dloi_macs) & set(new_devices))
                    publish_dloi_state(client, config['MQTT_TOPIC_DLOI'], dloi_name, dloi_present)

                print(f"Sleeping for {SLEEP_TIMEOUT} seconds...\n")
                time.sleep(SLEEP_TIMEOUT)

    finally:
        print("Interrupted, logging out.")
        router.logout()
        client.disconnect()
