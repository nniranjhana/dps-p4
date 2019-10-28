# Data Plane Security with P4 (DPS-P4)

## What do we have here?

This repository consists of P4 programs that detect layer-2 spoofing attacks in the SDN data plane.

An IP source guard, DHCP snooping detection and ARP inspection for software switches are implemented in the [src/](https://github.com/nniranjhana/dps-p4/tree/master/src/sw) directory.

The detection of IP spoofing attacks in hardware (NetFPGA) is implemented in the [netfpga/](https://github.com/nniranjhana/dps-p4/tree/master/src/hw/netfpga) directory.

## How do I get started?

Follow the instructions outlined in [Getting Started with P4](https://p4.org/p4/getting-started-with-p4.html) to have a working setup to test the P4 programs.
You might alternatively also want to [read about P4](https://www.sigcomm.org/sites/default/files/ccr/papers/2014/July/0000000-0000004.pdf) and try out the [tutorials](https://github.com/p4lang/tutorials) for a better understanding.

Motivation and more detailed information can be found in our [paper](https://ants2019.ieee-comsoc-ants.org/).

### Acknowledgements
This work was supported by a DST-FIST grant (SR/FST/ETI-423/2016) from Government of India (2017-2022) and by a Mid-Career Institute Research and Development Award (IRDA) from IIT Madras (2017--2020). The authors (Niranjhana Narayanan, Ganesh C. Sankaran, Krishna M. Sivalingam) are also pleased to acknowledge the efforts of Phanindra Palagummi, Harsh Gondaliya and the CoreEL team for their help with the NetFPGA systems.
