# vodafone-mqtt

**MQTT exporter for Vodafone Station / Arris TG3442DE routers**

## Overview
This project provides an MQTT exporter to monitor device connectivity for Vodafone Station routers. It has been tested on the following router configuration:

- **Firmware Version:** `AR01.04.137.04_021624_7249.PC20.10`
- **Hardware Version:** `11`

The exporter can be integrated with Home Assistant or other MQTT-compatible platforms to provide real-time network monitoring and automation.

## Example Home Assistant Configuration
To use this exporter with Home Assistant, add the following configuration to your `configuration.yml` file:

```yaml
mqtt:
  sensor:
  - name: "Example sensor"
    state_topic: "home/devices/aa:aa:aa:aa:aa:aa/state"
    unique_id: "aa:aa:aa:aa:aa:aa_state"
    availability:
      - topic: "home/devices/aa:aa:aa:aa:aa:aa/state"

  binary_sensor:
  - name: "Example binary sensor"
    state_topic: "home/devices/aa:aa:aa:aa:aa:aa/state"
    payload_on: "connected"
    payload_off: "disconnected"
    device_class: presence

  device_tracker:
  - name: "Example device tracker based on DLOI"
    state_topic: "vodafone/dloi/test-device-list"
    payload_on: "True"
    payload_off: "False"
```

## Features
- Monitors connectivity of devices on your router.
- Publishes real-time device states (`connected` or `disconnected`) to MQTT topics.
  - Per device: `vodafone/device/{MAC}/state`
  - All devices: `vodafone/devices/connected`
- Supports Device List of Interest (DLOI):
  - Publishes True if any device from a list is connected, and False if none are connected:
    - `vodafone/dloi/{dloi_name}`

### Device list of Interest (DLOI)
  - The same thing but publishes `True` if any device from the list is connected and `False` if none.

## Installation and Usage
1. Clone the repository:

```bash
git clone https://github.com/vggscqq/vodafone-mqtt.git
cd vodafone-mqtt
```

2. Install the dependencies:
```bash
pip install -r requirements.txt
```

3. Create a config.yml file in the root directory with your router and MQTT configuration:
[config.yml](https://github.com/vggscqq/vodafone-mqtt/blob/main/config.yml_example)

4. Run the script:
```bash
python vodafone_mqtt.py
```

5. Integrate to Home Assistant.

## Contribution
If your router is supported or you add support for a different firmware or hardware version, feel free to contribute back to this project.

## License
This project is licensed under the GPL License.
