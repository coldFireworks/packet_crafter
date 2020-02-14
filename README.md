[![crates.io](https://img.shields.io/crates/v/packet_crafter.svg)](https://crates.io/crates/packet_crafter)

#  packet_crafter

Create, parse and manipulate data packets. This crate provides tools which can be used to easily work with data packets using an intuitive high level interface. If you would like to request any features or improvements please just open an issue, likewise to report any bugs of course.

*Please note that any type annotations in this documentation, such as `let data: Vec<u8> = packet.into_vec();`, are only added for clarity, and are not required in your code.*

## usage

### create new packet

***Step 1***

Import the appropriate parts of the package, and create a new packet struct in order to start populating it. There are two methods of creating a new packet, method 1 will set the capacity of the internal buffer to the appropriate length for the given protocols, and method 2 will just create a totally empty packet with the internal buffer capacity set to 0. Method 1 is preferred for large packets as it will be slightly more efficient as there will be no need to constantly increase the cpacity of the buffer each time data is added


	extern crate packet_crafter;
	
	use packet_crafter::{
		//import sub-modules
		headers,
		protocol_numbers,
		ethertype_numbers,
		
		//import data types
		Packet,
		Protocol
	};
	
	fn main() {		
		// method 1 (preferred)
		let mut new_packet = Packet::new(
			vec![
				Protocol::ETH,
				Protocol::IP,
				Protocol::TCP
			]
		);
	
		// method 2
		let mut new_packet = Packet::new_empty();

***Step 2***

Create the headers and add them into the packet. Here we are going to go with the packet structure in method 1 of step 1, which Ethernet > Ip > TCP
		
		new_packet.add_header(
			headers::EthernetHeader::new(
				[6,5,4,3,2,1], // source mac address
				[1,2,3,4,5,6], // destination mac address
				ethertype_numbers::ETHERTYPE_IPV4
			)
		);

		new_packet.add_header(
			headers::IpHeader::new(
				[192, 168, 1, 128], // source IP
				[192, 168, 1, 38], // destination IP
				Protocol::TCP // next protocol
			)
		);

		new_packet.add_header(
			headers::TcpHeader::new(
				3838, // source port
				3838 // destination port
			)
		);

***Step 3***

This step may not always be necessary, in cases like ICMP echos where there does not need to be data because only the headers are read. In many cases, however, you likely will want to add some payload data. Again, there are two ways to do this, method 1 will overwrite the exisiting payload data (if this is a new packet there will be none anyway, but if it is a packet that has been parsed from raw data, there may be some), and method 2 will append to the existing payload data. Notice the absence of the `.collect()` in method 2. The code would still work with it, however, it is not needed. you will see why if you look at the function signature in the source.
		
		
		// method 1
		new_packet.set_payload("Hello, world!".bytes().collect());
		
		// method 2
		new_packet.extend_payload("Hello, world!".bytes());
***Step 4***

The data is now ready, so we just need to bake the packet. This is where checksum fields and length fields duch as the one in the IP header will be populated (see [this doc page](https://docs.rs/packet_crafter/0.1.4/packet_crafter/headers/trait.Header.html#tymethod.make) for an explanation of why I decided to calculate these even though the OS will likely overwrite them)
		
		let data: Vec<u8> = new_packet.into_vec();
	}
*always remember that `&Vec<u8>` can be passed into functions expecting `&[u8]` :)*
	
### parse a packet

Parsing a packet is made very simple, as long as the packet is one starting with either the ip header or the ethernet II header:

	extern crate packet_crafter;

	use packet_crafter::Packet;

	fn main() {
		let raw_data: &[u8] = your_function_to_read_a_packet_from_socket();
		let parsed_packet: Result<Packet, packet_crafter::ParseError> = Packet::parse(raw_data);
	}

### manipulating a packet

Lets say we've just parsed the packet which is created in the *create new packet* example, so it's an ETH > IP > TCP packet, and we want to update the desination port of the tcp field as well as the destination ip:

	// imports elided

	fn main() {
		let raw_data: &[u8] = your_function_to_read_a_packet_from_socket();
		let mut packet = Packet::parse(raw_data).unwrap();
		let mut tcp_header = packet.get_tcp_header().unwrap();
		tcp_header.set_dst_port(21);
		let mut ip_header = packet.get_ip_header().unwrap();
		ip_header.set_dst_ip([192, 168, 1, 84]);
		packet.update_header(ip_header);

		// packet is now good to go, so make it and then send it:
		let data = packet.into_vec();
		your_function_to_send_packet_down_socket(&data);
	}