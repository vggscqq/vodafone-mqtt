from pathlib import Path
import yaml
import paho.mqtt.client as mqtt

def load_config():
    try:
        config_path = Path('config.yml')
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)

        # Create variables from config
        MQTT_BROKER = config['mqtt']['broker']
        MQTT_PORT = config['mqtt']['port']
        MQTT_USERNAME = config['mqtt']['username']
        MQTT_PASSWORD = config['mqtt']['password']
        MQTT_TOPIC = config['mqtt']['topic_devs']

        MQTT_DOIS = {}
        for doi in list(config['doi'].keys()):
            MQTT_DOIS[doi] = []
            for doi_mac in config['doi'][doi]['macs']:
                MQTT_DOIS[doi].append(doi_mac)

        return {
            'MQTT_BROKER': MQTT_BROKER,
            'MQTT_PORT': MQTT_PORT,
            'MQTT_USERNAME': MQTT_USERNAME,
            'MQTT_PASSWORD': MQTT_PASSWORD,
            'MQTT_TOPIC': MQTT_TOPIC,
            'MQTT_DOIS': MQTT_DOIS
        }
    except FileNotFoundError:
        raise FileNotFoundError("config.yml file not found")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing config.yml: {str(e)}")
    except KeyError as e:
        raise KeyError(f"Missing required configuration key: {str(e)}")

config = load_config()

# Callback for when the client connects to the broker
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker!")
        client.subscribe(config['MQTT_TOPIC'])
        print(f"Subscribed to topic: {config['MQTT_TOPIC']}")
    else:
        print(f"Failed to connect, return code {rc}")

# Callback for when a message is received
def on_message(client, userdata, msg):
    # print any msg recieved
    print(f"Received message on topic {msg.topic}") #: {msg.payload.decode()}")
    macs = msg.payload.decode()[1:-1].split(' ')
    for i in macs:
        print(f"\t{i}")

    # you have a list of macs. Find yout which dois are present
    for doi in config['MQTT_DOIS']:
        if set(config['MQTT_DOIS'][doi]) & set(macs):
            print(f"DOI {doi} is present")
            #publish_devices(config['MQTT_BROKER'], config['MQTT_PORT'], config['MQTT_USERNAME'], config['MQTT_PASSWORD'], config['MQTT_TOPIC'], macs)

# Initialize MQTT client
client = mqtt.Client()
client.username_pw_set(config['MQTT_USERNAME'], config['MQTT_PASSWORD'])
client.on_connect = on_connect
client.on_message = on_message

# Connect to the MQTT broker
client.connect(config['MQTT_BROKER'], config['MQTT_PORT'], 60)

# Start the loop
client.loop_forever()
