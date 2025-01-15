# vodafone-mqtt

**MQTT exporter for Vodafone Station / Arris TG3442DE routers**

## Overview
This project provides an MQTT exporter to monitor device connectivity for Vodafone Station routers. It has been tested on the following router configuration:

- **Firmware Version:** `AR01.04.137.04_021624_7249.PC20.10`
- **Hardware Version:** `11`

The exporter can be integrated to Home Assistant.

## Example Home Assistant Configuration
To use this exporter with Home Assistant, add the following configuration to your `configuration.yml` file:

```yaml
mqtt:
  sensor:
    - name: "vgscq-phone State"
      state_topic: "home/devices/aa:aa:aa:aa:aa:aa/state"
      unique_id: "aa:aa:aa:aa:aa:aa_state"
      availability:
        - topic: "home/devices/aa:aa:aa:aa:aa:aa/state"
```

This configuration listens to the state of a device with MAC address `aa:aa:aa:aa:aa:aa`. When the device connects or disconnects from the network, the MQTT client publishes `"connected"` or `"disconnected"` messages to the `home/devices/aa:aa:aa:aa:aa:aa/state` topic.

## Features
- Monitors connectivity of devices on your router.
- Publishes real-time device states (`connected` or `disconnected`) to MQTT topics.

### Planned Features (TODO)
- Publish the total number of devices connected on LAN and Wi-Fi.

## Contribution
If your router is supported or you add support for a different firmware or hardware version, feel free to contribute back to this project.

## License
This project is licensed under the GPL License.
