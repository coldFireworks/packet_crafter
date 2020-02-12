#  packet_crafter

Create, parse and manipulate data packets. This crate provides tools which can be used to easily work with data packets using an intuitive high level interface. If you would like to request any features or improvements please just open an issue, likewise to report any bugs of course.

## usage

#### create new packet


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
		// ************************************
		// *** step 1: create packet struct ***
		// ************************************
		
		// method 1 (preferred): an empty packet with the buffer
		// capacity set to the appropriate size for the given protocols
		let mut new_packet = Packet::new(
			vec![
				Protocol::ETH,
				Protocol::IP,
				Protocol::TCP
			]
		);
	
		// method 2: empty packet, buffer capacity 0
		let mut new_packet = Packet::new_empty();
		
		// ****************************************************
		// *** step 2: create and add headers to the packet ***
		// ****************************************************
		// lets assume we're going with the packet structure shown in
		// method 1, as this would be a common use...
		
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
		
		// *******************************************************
		// *** step 3 (not always necessary): add payload data ***
		// *******************************************************
		
		// this will overwrite any existing payload data...
		new_packet.set_payload("Hello, world!".bytes().collect());
		
		// ...whereas this will append to existing payload data:
		new_packet.extend_payload("Hello, world!".bytes())
		// notice the absence of the `.collect()` here. The
		// code would still work with it, however, it is not needed.
		// you will see why if you look at the function signature in the source

		// *******************************
		// *** step 4: bake the packet ***
		// *******************************
		
		let data: Vec<u8> = new_packet.into_vec(); // type annotation is just for clarity
		// remember that &Vec<u8> can be passed into functions expecting a &[u8] :)
	}
	
####  parse a packet

Still in progress, I'll add proper documentation when I'm confident that this feature is usable.
