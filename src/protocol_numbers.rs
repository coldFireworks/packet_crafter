// note that 0 can also be used for IP v6 hop-by-hop options

/// dummy for IP
pub const IPPROTO_IP: u8          = 0;
/// control message protocol
pub const IPPROTO_ICMP: u8        = 1;
/// group mgmt protocol
pub const IPPROTO_IGMP: u8        = 2;
/// gateway^2 (deprecated)
pub const IPPROTO_GGP: u8         = 3;
/// IPv4 encapsulation
pub const IPPROTO_IPV4: u8        = 4;
/// Stream
pub const IPPROTO_ST: u8          = 5;
/// tcp
pub const IPPROTO_TCP: u8         = 6;
/// Stream protocol II
pub const IPPROTO_STII: u8        = 7;
/// exterior gateway protocol
pub const IPPROTO_EGP: u8         = 8;
/// private interior gateway
pub const IPPROTO_PIGP: u8        = 9;
/// BBN RCC Monitoring
pub const IPPROTO_RCCMON: u8      = 10;
/// network voice protoco
pub const IPPROTO_NVPII: u8       = 11;
/// pup
pub const IPPROTO_PUP: u8         = 12;
/// Argus
pub const IPPROTO_ARGUS: u8       = 13;
/// EMCON
pub const IPPROTO_EMCON: u8       = 14;
/// Cross Net Debugger
pub const IPPROTO_XNET: u8        = 15;
/// Chao
pub const IPPROTO_CHAOS: u8       = 16;
/// user datagram protocol
pub const IPPROTO_UDP: u8         = 17;
/// Multiplexing
pub const IPPROTO_MUX: u8         = 18;
/// DCN Measurement Subsystems
pub const IPPROTO_MEAS: u8        = 19;
/// Host Monitoring
pub const IPPROTO_HMP: u8         = 20;
/// Packet Radio Measurement
pub const IPPROTO_PRM: u8         = 21;
/// xns idp
pub const IPPROTO_IDP: u8         = 22;
/// Trunk-1
pub const IPPROTO_TRUNK1: u8      = 23;
/// Trunk-2
pub const IPPROTO_TRUNK2: u8      = 24;
/// Leaf-1
pub const IPPROTO_LEAF1: u8       = 25;
/// Leaf-2
pub const IPPROTO_LEAF2: u8       = 26;
/// Reliable Data
pub const IPPROTO_RDP: u8         = 27;
/// Reliable Transaction
pub const IPPROTO_IRTP: u8        = 28;
/// tp-4 w/ class negotiation
pub const IPPROTO_TP: u8          = 29;
/// Bulk Data Transfer
pub const IPPROTO_BLT: u8         = 30;
/// Network Services
pub const IPPROTO_NSP: u8         = 31;
/// Merit Internodal
pub const IPPROTO_INP: u8         = 32;
/// Sequential Exchange
pub const IPPROTO_SEP: u8         = 33;
/// Third Party Connect
pub const IPPROTO_3PC: u8         = 34;
/// InterDomain Policy Routing
pub const IPPROTO_IDPR: u8        = 35;
/// XTP
pub const IPPROTO_XTP: u8         = 36;
/// Datagram Delivery
pub const IPPROTO_DDP: u8         = 37;
/// Control Message Transport
pub const IPPROTO_CMTP: u8        = 38;
/// TP++ Transport
pub const IPPROTO_TPXX: u8        = 39;
/// IL transport protocol
pub const IPPROTO_IL: u8          = 40;
/// IP6 header
pub const IPPROTO_IPV6: u8        = 41;
/// Source Demand Routing
pub const IPPROTO_SDRP: u8        = 42;
/// IP6 routing header
pub const IPPROTO_ROUTING: u8     = 43;
/// IP6 fragmentation header
pub const IPPROTO_FRAGMENT: u8    = 44;
/// InterDomain Routin
pub const IPPROTO_IDRP: u8        = 45;
/// resource reservation
pub const IPPROTO_RSVP: u8        = 46;
/// General Routing Encap.
pub const IPPROTO_GRE: u8         = 47;
/// Mobile Host Routing
pub const IPPROTO_MHRP: u8        = 48;
/// BHA
pub const IPPROTO_BHA: u8         = 49;
/// IP6 Encap Sec. Payload
pub const IPPROTO_ESP: u8         = 50;
/// IP6 Auth Header
pub const IPPROTO_AH: u8          = 51;
/// Integ. Net Layer Security
pub const IPPROTO_INLSP: u8       = 52;
/// IP with encryption
pub const IPPROTO_SWIPE: u8       = 53;
/// Next Hop Resolution
pub const IPPROTO_NHRP: u8        = 54;

// 55-57: Unassigned

/// ICMP6
pub const IPPROTO_ICMPV6: u8      = 58;
/// IP6 no next header
pub const IPPROTO_NONE: u8        = 59;
/// IP6 destination option
pub const IPPROTO_DSTOPTS: u8     = 60;
/// any host internal protocol
pub const IPPROTO_AHIP: u8        = 61;
/// CFTP
pub const IPPROTO_CFTP: u8        = 62;
/// "hello" routing protocol
pub const IPPROTO_HELLO: u8       = 63;
/// SATNET/Backroom EXPAK
pub const IPPROTO_SATEXPAK: u8    = 64;
/// Kryptolan
pub const IPPROTO_KRYPTOLAN: u8   = 65;
/// Remote Virtual Disk
pub const IPPROTO_RVD: u8         = 66;
/// Pluribus Packet Core
pub const IPPROTO_IPPC: u8        = 67;
/// Any distributed FS
pub const IPPROTO_ADFS: u8        = 68;
/// Satnet Monitoring
pub const IPPROTO_SATMON: u8      = 69;
/// VISA Protocol
pub const IPPROTO_VISA: u8        = 70;
/// Packet Core Utility
pub const IPPROTO_IPCV: u8        = 71;
/// Comp. Prot. Net. Executive
pub const IPPROTO_CPNX: u8        = 72;
/// Comp. Prot. HeartBeat
pub const IPPROTO_CPHB: u8        = 73;
/// Wang Span Network
pub const IPPROTO_WSN: u8         = 74;
/// Packet Video Protocol
pub const IPPROTO_PVP: u8         = 75;
/// BackRoom SATNET Monitoring
pub const IPPROTO_BRSATMON: u8    = 76;
/// Sun net disk proto (temp.)
pub const IPPROTO_ND: u8          = 77;
/// WIDEBAND Monitoring
pub const IPPROTO_WBMON: u8       = 78;
/// WIDEBAND EXPAK
pub const IPPROTO_WBEXPAK: u8     = 79;
/// ISO cnlp
pub const IPPROTO_EON: u8         = 80;
/// VMTP
pub const IPPROTO_VMTP: u8        = 81;
/// Secure VMTP
pub const IPPROTO_SVMTP: u8       = 82;
/// Banyon VINES
pub const IPPROTO_VINES: u8       = 83;
/// TTP
pub const IPPROTO_TTP: u8         = 84;
/// NSFNET-IGP
pub const IPPROTO_IGP: u8         = 85;
/// dissimilar gateway prot.
pub const IPPROTO_DGP: u8         = 86;
/// TCF
pub const IPPROTO_TCF: u8         = 87;
/// Cisco/GXS IGRP
pub const IPPROTO_IGRP: u8        = 88;
/// OSPFIGP
pub const IPPROTO_OSPFIGP: u8     = 89;
/// Strite RPC protocol
pub const IPPROTO_SRPC: u8        = 90;
/// Locus Address Resoloution
pub const IPPROTO_LARP: u8        = 91;
/// Multicast Transport
pub const IPPROTO_MTP: u8         = 92;
/// AX.25 Frames
pub const IPPROTO_AX25: u8        = 93;
/// IP encapsulated in IP
pub const IPPROTO_IPIP: u8        = 94;
/// Mobile Int.ing control
pub const IPPROTO_MICP: u8        = 95;
/// Semaphore Comm. security
pub const IPPROTO_SCCSP: u8       = 96;
/// Ethernet IP encapsulation
pub const IPPROTO_ETHERIP: u8     = 97;
/// encapsulation header
pub const IPPROTO_ENCAP: u8       = 98;
/// any private encr. scheme
pub const IPPROTO_APES: u8        = 99;
/// GMT
pub const IPPROTO_GMTP: u8        = 100;

// 101-254: Partly Unassigned

/// Protocol Independent Mcast
pub const IPPROTO_PIM: u8         = 103;
/// payload compression (IPComp)
pub const IPPROTO_IPCOMP: u8      = 108;
/// PGM
pub const IPPROTO_PGM: u8         = 113;
/// SCTP
pub const IPPROTO_SCTP: u8        = 132;

// BSD Private, local use, namespace incursion

/// divert pseudo-protocol
pub const IPPROTO_DIVERT: u8      = 254;
/// raw IP packet
pub const IPPROTO_RAW: u8         = 255;