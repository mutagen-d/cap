export type IEthernetInfo = {
  dstmac: string;
  srcmac: string;
  type?: number;
  length?: number;
  vlan?: {
    priority: number;
    CFI: boolean;
    VID: number;
  }
}
export declare const Ethernet: (b: Buffer, offset?: number) => { info: IEthernetInfo; offset: number; }

export type IIPv4Info = {
  hdrlen: number,
  dscp: number,
  ecn: number,
  totallen: number,
  id: number,
  flags: number,
  fragoffset: number,
  ttl: number,
  protocol: number,
  hdrchecksum: undefined,
  srcaddr: string,
  dstaddr: string,
  options?: any
}

export declare const IPV4: (b: Buffer, offset?: number) => { info: IIPv4Info; offset: number; hdrlen: number; }

export type IIPv6Info = {
  class: number
  flowLabel: number
  extensions: number
  protocol?: number
  hopLimit: number
  srcaddr: string
  dstaddr: string
}

export declare const IPV6: (b: Buffer, offset?: number) => { info: IIPv6Info; offset: number; payloadlen: number; }

export type IICMPv4InfoBase = {
  type: number;
  code: number;
  checksum: number;
}

export type IICMPv4IPHeader = {
  info: IIPv4Info;
  hdrlen: number;
}

export type IICMPv4Info = IICMPv4InfoBase & ({
  seqno: number;
  identifier: number;
  originate?: number;
  receive?: number;
  transmit?: number;
  mask?: string;
} | {
  nextHopMTU?: number;
  gatewayAddr?: string;
  pointer?: number;
  IPHeader: IICMPv4IPHeader
  dataOffset: number;
} | {
  lifetime: number;
  addrs: { addr: string; pref: number; }[];
} | {
  outHopCount: number;
  retHopCount: number;
  outLnkSpeed: number;
  outLnkMTU: number;
})

export declare const ICMPV4: (b: Buffer, offset?: number) => { info: IICMPv4Info; offset: number; }

export type ITCPInfo = {
  srcport: number
  dstport: number
  seqno: number
  ackno?: number
  flags: number
  window: number
  checksum: number
  urgentptr?: number
  options?: any
}

export declare const TCP: (b: Buffer, offset?: number) => { info: ITCPInfo; hdrlen: number; offset: number; }

export type IUDPInfo = {
  srcport: number
  dstport: number
  length: number
  checksum: number
}

export declare const UDP: (b: Buffer, offset?: number) => { info: IUDPInfo; offset: number; }

export type ISCTPInfo = {
  srcport: number
  dstport: number
  verifyTag: number
  checksum: number
  chunks?: { type: number; flags: number; offset: number; length: number; }[]
}

export declare const SCTP: (b: Buffer, offset?: number) => { info: ISCTPInfo; offset: number; }

export type IARPInfo = {
  hardwareaddr: number
  protocol: number
  hdrlen: number
  protlen: number
  opcode: number
  sendermac: string
  senderip: string
  targetmac: string
  targetip: string
}

export declare const ARP: (b: Buffer, offset?: number) => { info: IARPInfo; offset: number; }

type REVERSEKEY<TOBJ, K extends keyof TOBJ = keyof TOBJ> = {
  [key in TOBJ[K]]: K
}

export declare const PROTOCOL: IPROTOCOL;

export type IPROTOCOL = {
  ETHERNET: ETHERNET
  & REVERSEKEY<ETHERNET, 'IPV4'>
  & REVERSEKEY<ETHERNET, 'X.75'>
  & REVERSEKEY<ETHERNET, 'CHAOSNET'>
  & REVERSEKEY<ETHERNET, 'X.25'>
  & REVERSEKEY<ETHERNET, 'ARP'>
  & REVERSEKEY<ETHERNET, 'ARP-RELAY'>
  & REVERSEKEY<ETHERNET, 'TRILL'>
  & REVERSEKEY<ETHERNET, 'L2-IS-IS'>
  & REVERSEKEY<ETHERNET, 'ARP-REVERSE'>
  & REVERSEKEY<ETHERNET, 'APPLETALK'>
  & REVERSEKEY<ETHERNET, 'APPLETALK-AARP'>
  & REVERSEKEY<ETHERNET, 'VLAN'>
  & REVERSEKEY<ETHERNET, 'SNMP'>
  & REVERSEKEY<ETHERNET, 'XTP'>
  & REVERSEKEY<ETHERNET, 'IPV6'>
  & REVERSEKEY<ETHERNET, 'TCPIP-COMPRESS'>
  & REVERSEKEY<ETHERNET, 'PPP'>
  & REVERSEKEY<ETHERNET, 'GSMP'>
  & REVERSEKEY<ETHERNET, 'PPPOE-DISCOVER'>
  & REVERSEKEY<ETHERNET, 'PPPOE-SESSION'>
  & REVERSEKEY<ETHERNET, 'LOOPBACK'>
  IP: IP & IP_PART2
}

type ETHERNET = {
  // Taken from (as of 2012-03-16):
  //     http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.txt
  'IPV4': 2048, // Internet IP (IPv4)                                    [IANA]
  'X.75': 2049, // X.75 Internet                                [Neil_Sembower]
  'CHAOSNET': 2052, // Chaosnet                                 [Neil_Sembower]
  'X.25': 2053, // X.25 Level 3                                 [Neil_Sembower]
  'ARP': 2054, // ARP                                                    [IANA]
  'ARP-RELAY': 2056, // Frame Relay ARP                               [RFC1701]
  'TRILL': 8947, // TRILL                                             [RFC6325]
  'L2-IS-IS': 8948, // L2-IS-IS                                       [RFC6325]
  'ARP-REVERSE': 32821, // Reverse ARP                 [RFC903][Joseph_Murdock]
  'APPLETALK': 32923, // Appletalk                              [Neil_Sembower]
  'APPLETALK-AARP': 33011, // AppleTalk AARP (Kinetics)         [Neil_Sembower]
  'VLAN': 33024, // IEEE 802.1Q VLAN-tagged frames (initially Wellfleet)
  'SNMP': 33100, // SNMP                                     [Joyce_K_Reynolds]
  'XTP': 33149, // XTP                                          [Neil_Sembower]
  'IPV6': 34525, // IPv6                                                 [IANA]
  'TCPIP-COMPRESS': 34667, // TCP/IP Compression                      [RFC1144]
  'PPP': 34827, // PPP                                                   [IANA]
  'GSMP': 34828, // GSMP                                                 [IANA]
  'PPPOE-DISCOVER': 34915, // PPPoE Discovery Stage                   [RFC2516]
  'PPPOE-SESSION': 34916, // PPPoE Session Stage                      [RFC2516]
  'LOOPBACK': 36864 // Loopback                                 [Neil_Sembower]
}

type IP = {
  // Taken from (as of 2012-10-17):
  //     http://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt
  'HOPOPT': 0, // IPv6 Hop-by-Hop Option                             [RFC2460]
  'ICMP': 1, // Internet Control Message                              [RFC792]
  'IGMP': 2, // Internet Group Management                            [RFC1112]
  'GGP': 3, // Gateway-to-Gateway                                     [RFC823]
  'IPV4': 4, // IPv4 encapsulation                                   [RFC2003]
  'ST': 5, // Stream                                        [RFC1190][RFC1819]
  'TCP': 6, // Transmission Control                                   [RFC793]
  'CBT': 7, // CBT                                            [Tony_Ballardie]
  'EGP': 8, // Exterior Gateway Protocol                 [RFC888][David_Mills]
  'IGP': 9, // any private interior gateway (used by
  // [Internet_Assigned_Numbers_Authority] Cisco for their IGRP)
  'BBN-RCC-MON': 10, // BBN RCC Monitoring                     [Steve_Chipman]
  'NVP-II': 11, // Network Voice Protocol               [RFC741][Steve_Casner]
  'PUP': 12, // PUP            [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe,
  //                 "PUP: An Internetwork Architecture",
  //                 XEROX Palo Alto Research Center, CSL-79-10,
  //                 July 1979; also in IEEE Transactions on
  //                 Communication, Volume COM-28, Number 4,
  //                 April 1980.]
  //                                                      [[XEROX]]
  'ARGUS': 13, // ARGUS                                   [Robert_W_Scheifler]
  'EMCON': 14, // EMCON                                    [<mystery contact>]
  'XNET': 15, // Cross Net Debugger       [Haverty, J.,
  //                           "XNET Formats for Internet Protocol
  //                            Version 4",
  //                           IEN 158, October 1980.]
  //                                                [Jack_Haverty]
  'CHAOS': 16, // Chaos                                       [J_Noel_Chiappa]
  'UDP': 17, // User Datagram                             [RFC768][Jon_Postel]
  'MUX': 18, // Multiplexing                         [Cohen, D. and J. Postel,
  //                                       "Multiplexing Protocol",
  //                                       IEN 90, USC/Information
  //                                       Sciences Institute,
  //                                       May 1979.]
  //                                                   [Jon_Postel]
  'DCN-MEAS': 19, // DCN Measurement Subsystems                  [David_Mills]
  'HMP': 20, // Host Monitoring                        [RFC869][Robert_Hinden]
  'PRM': 21, // Packet Radio Measurement                         [Zaw_Sing_Su]
  'XNS-IDP': 22, // XEROX NS IDP       ["The Ethernet, A Local Area Network: 
  //                      Data Link Layer and Physical Layer
  //                      Specification", AA-K759B-TK,
  //                      Digital Equipment Corporation,
  //                      Maynard, MA. Also as: "The Ethernet 
  //                      - A Local Area Network",
  //                      Version 1.0,
  //                      Digital Equipment Corporation,
  //                      Intel Corporation, Xerox Corporation,
  //                      September 1980. And: "The Ethernet,
  //                       A Local Area Network: Data Link
  //                       Layer and Physical Layer
  //                       Specifications",
  //                      Digital, Intel and Xerox,
  //                      November 1982. And: XEROX,
  //                      "The Ethernet, A Local Area Network: 
  //                       Data Link Layer and Physical Layer
  //                       Specification",
  //                      X3T51/80-50, Xerox Corporation,
  //                      Stamford, CT., October 1980.]
  //                                                  [[XEROX]]
  'TRUNK-1': 23, // Trunk-1                                      [Barry_Boehm]
  'TRUNK-2': 24, // Trunk-2                                      [Barry_Boehm]
  'LEAF-1': 25, // Leaf-1                                        [Barry_Boehm]
  'LEAF-2': 26, // Leaf-2                                        [Barry_Boehm]
  'RDP': 27, // Reliable Data Protocol                 [RFC908][Robert_Hinden]
  'IRTP': 28, // Internet Reliable Transaction          [RFC938][Trudy_Miller]
  'ISO-TP4': 29, // ISO Transport Protocol Class 4 [RFC905][<mystery contact>]
  'NETBLT': 30, // Bulk Data Transfer Protocol           [RFC969][David_Clark]
  'MFE-NSP': 31, // MFE Network Services Protocol   [Shuttleworth, B.,
  //                                  "A Documentary of MFENet,
  //                                   a National Computer
  //                                   Network", UCRL-52317,
  //                                   Lawrence Livermore Labs,
  //                                   Livermore, California,
  //                                   June 1977.]
  //                                             [Barry_Howard]
  'MERIT-INP': 32, // MERIT Internodal Protocol            [Hans_Werner_Braun]
  'DCCP': 33, // Datagram Congestion Control Protocol                [RFC4340]
  '3PC': 34, // Third Party Connect Protocol              [Stuart_A_Friedberg]
  'IDPR': 35, // Inter-Domain Policy Routing Protocol      [Martha_Steenstrup]
  'XTP': 36, // XTP                                             [Greg_Chesson]
  'DDP': 37, // Datagram Delivery Protocol                      [Wesley_Craig]
  'IDPR-CMTP': 38, // IDPR Control Message Transport Proto [Martha_Steenstrup]
  'TP++': 39, // TP++ Transport Protocol                       [Dirk_Fromhein]
  'IL': 40, // IL Transport Protocol                           [Dave_Presotto]
  'IPV6': 41, // IPv6 encapsulation                                  [RFC2473]
  'SDRP': 42, // Source Demand Routing Protocol               [Deborah_Estrin]
  'IPV6-ROUTE': 43, // Routing Header for IPv6                 [Steve_Deering]
  'IPV6-FRAG': 44, // Fragment Header for IPv6                 [Steve_Deering]
  'IDRP': 45, // Inter-Domain Routing Protocol                     [Sue_Hares]
  'RSVP': 46, // Reservation Protocol           [RFC2205][RFC3209][Bob_Braden]
  'GRE': 47, // Generic Routing Encapsulation               [RFC1701][Tony_Li]
  'DSR': 48, // Dynamic Source Routing Protocol                      [RFC4728]
  'BNA': 49, // BNA                                             [Gary Salamon]
  'ESP': 50, // Encap Security Payload                               [RFC4303]
  'AH': 51, // Authentication Header                                 [RFC4302]
  'I-NLSP': 52, // Integrated Net Layer Security TUBA         [K_Robert_Glenn]
  'SWIPE': 53, // IP with Encryption                          [John_Ioannidis]
  'NARP': 54, // NBMA Address Resolution Protocol                    [RFC1735]
  'MOBILE': 55, // IP Mobility                               [Charlie_Perkins]
  'TLSP': 56, // Transport Layer Security Protocol using Kryptonet key
  // management
  //                                              [Christer_Oberg]
  'SKIP': 57, // SKIP                                            [Tom_Markson]
  'ICMPV6': 58, // ICMP for IPv6                                     [RFC2460]
  'IPV6-NONXT': 59, // No Next Header for IPv6                       [RFC2460]
  'IPV6-OPTS': 60, // Destination Options for IPv6                   [RFC2460]
  // 61 any host internal protocol       [Internet_Assigned_Numbers_Authority]
  'CFTP': 62, // CFTP                                [Forsdick, H., "CFTP",
  //                                      Network Message,
  //                                      Bolt Beranek and Newman,
  //                                      January 1982.]
  //                                              [Harry_Forsdick]
  // 63 any local network                [Internet_Assigned_Numbers_Authority]
  'SAT-EXPAK': 64, // SATNET and Backroom EXPAK            [Steven_Blumenthal]
  'KRYPTOLAN': 65, // Kryptolan                                     [Paul Liu]
  'RVD': 66, // MIT Remote Virtual Disk Protocol           [Michael_Greenwald]
  'IPPC': 67, // Internet Pluribus Packet Core             [Steven_Blumenthal]
  // 68 any distributed file system      [Internet_Assigned_Numbers_Authority]
  'SAT-MON': 69, // SATNET Monitoring                      [Steven_Blumenthal]
  'VISA': 70, // VISA Protocol                                   [Gene_Tsudik]
  'IPCV': 71, // Internet Packet Core Utility              [Steven_Blumenthal]
  'CPNX': 72, // Computer Protocol Network Executive         [David Mittnacht]
  'CPHB': 73, // Computer Protocol Heart Beat                [David Mittnacht]
  'WSN': 74, // Wang Span Network                            [Victor Dafoulas]
  'PVP': 75, // Packet Video Protocol                           [Steve_Casner]
  'BR-SAT-MON': 76, // Backroom SATNET Monitoring          [Steven_Blumenthal]
  'SUN-ND': 77, // SUN ND PROTOCOL-Temporary                  [William_Melohn]
  'WB-MON': 78, // WIDEBAND Monitoring                     [Steven_Blumenthal]
  'WB-EXPAK': 79, // WIDEBAND EXPAK                        [Steven_Blumenthal]
  'ISO-IP': 80, // ISO Internet Protocol                     [Marshall_T_Rose]
  'VMTP': 81, // VMTP                                          [Dave_Cheriton]
  'SECURE-VMTP': 82, // SECURE-VMTP                            [Dave_Cheriton]
  'VINES': 83, // VINES                                           [Brian Horn]
  'TTP': 84, // TTP                                              [Jim_Stevens]
  'IPTM': 84, // Protocol Internet Protocol Traffic Manager      [Jim_Stevens]
  'NSFNET-IGP': 85, // NSFNET-IGP                          [Hans_Werner_Braun]
  'DGP': 86, // Dissimilar Gateway Protocol   [M/A-COM Government Systems,
  //                                "Dissimilar Gateway Protocol
  //                                 Specification, Draft Version",
  //                                Contract no. CS901145,
  //                                November 16, 1987.]
  //                                                  [Mike_Little]
  'TCF': 87, // TCF                                       [Guillermo_A_Loyola]
  'EIGRP': 88, // EIGRP                    [Cisco Systems,
  //                           "Gateway Server Reference Manual",
  //                           Manual Revision B, January 10,
  //                           1988.]
  //                          [Guenther_Schreiner]
  'OSPFIGP': 89, // OSPFIGP              [RFC1583][RFC2328][RFC5340][John_Moy]
  'SPRITE-RPC': 90, // Sprite RPC Protocol   [Welch, B., "The Sprite Remote
  //                        Procedure Call System",
  //                        Technical Report,
  //                        UCB/Computer Science Dept.,
  //                        86/302, University of California
  //                        at Berkeley, June 1986.]
  //                       [Bruce Willins]
  'LARP': 91, // Locus Address Resolution Protocol                [Brian Horn]
  'MTP': 92, // Multicast Transport Protocol                 [Susie_Armstrong]
  'AX.25': 93, // AX.25 Frames                                  [Brian_Kantor]
  'IPIP': 94, // IP-within-IP Encapsulation Protocol          [John_Ioannidis]
  'MICP': 95, // Mobile Internetworking Control Pro.          [John_Ioannidis]
  'SCC-SP': 96, // Semaphore Communications Sec. Pro.            [Howard_Hart]
  'ETHERIP': 97, // Ethernet-within-IP Encapsulation                 [RFC3378]
  'ENCAP': 98, // Encapsulation Header              [RFC1241][Robert_Woodburn]
  // 99 any private encryption scheme    [Internet_Assigned_Numbers_Authority]
  'GMTP': 100, // GMTP                                                [[RXB5]]
  'IFMP': 101, // Ipsilon Flow Management Protocol                [Bob_Hinden]
  //                                       [November 1995, 1997.]
  'PNNI': 102, // PNNI over IP                                   [Ross_Callon]
  'PIM': 103, // Protocol Independent Multicast      [RFC4601][Dino_Farinacci]
  'ARIS': 104, // ARIS                                         [Nancy_Feldman]
  'SCPS': 105, // SCPS                                          [Robert_Durst]
  'QNX': 106, // QNX                                          [Michael_Hunter]
  'A/N': 107, // Active Networks                                  [Bob_Braden]
  'IPCOMP': 108, // IP Payload Compression Protocol                  [RFC2393]
  'SNP': 109, // Sitara Networks Protocol                 [Manickam_R_Sridhar]
  'COMPAQ-PEER': 110, // Compaq Peer Protocol                   [Victor_Volpe]
  'IPX-IN-IP': 111, // IPX in IP                                      [CJ_Lee]
  'VRRP': 112, // Virtual Router Redundancy Protocol                 [RFC5798]
  'PGM': 113, // PGM Reliable Transport Protocol               [Tony_Speakman]
  // 114 any 0-hop protocol              [Internet_Assigned_Numbers_Authority]
  'L2TP': 115, // Layer Two Tunneling Protocol        [RFC3931][Bernard_Aboba]
  'DDX': 116, // D-II Data Exchange (DDX)                        [John_Worley]
  'IATP': 117, // Interactive Agent Transfer Protocol            [John_Murphy]
  'STP': 118, // Schedule Transfer Protocol               [Jean_Michel_Pittet]
  'SRP': 119, // SpectraLink Radio Protocol                    [Mark_Hamilton]
  'UTI': 120, // UTI                                          [Peter_Lothberg]
  'SMP': 121, // Simple Message Protocol                         [Leif_Ekblad]
  'SM': 122, // SM                                             [Jon_Crowcroft]
  'PTP': 123, // Performance Transparency Protocol             [Michael_Welzl]
  'ISIS': 124, // over IPv4                                  [Tony_Przygienda]
  'FIRE': 125, //                                            [Criag_Partridge]
  'CRTP': 126, // Combat Radio Transport Protocol             [Robert_Sautter]
  'CRUDP': 127, // Combat Radio User Datagram                 [Robert_Sautter]
  'SSCOPMCE': 128, //                                             [Kurt_Waber]
  'IPLT': 129, //                                                 [[Hollbach]]
  'SPS': 130, // Secure Packet Shield                          [Bill_McIntosh]
  'PIPE': 131, // Private IP Encapsulation within IP          [Bernhard_Petri]
  'SCTP': 132, // Stream Control Transmission Protocol     [Randall_R_Stewart]
  'FC': 133, // Fibre Channel                      [Murali_Rajagopal][RFC6172]
  'RSVP-E2E-IGNORE': 134, //                                         [RFC3175]
  'MOBILITY HEADER': 135, //                                         [RFC6275]
  'UDPLITE': 136, //                                                 [RFC3828]
  'MPLS-IN-IP': 137, //                                              [RFC4023]
  'MANET': 138, // MANET Protocols                                   [RFC5498]
  'HIP': 139, // Host Identity Protocol                              [RFC5201]
  'SHIM6': 140, // Shim6 Protocol                                    [RFC5533]
  'WESP': 141, // Wrapped Encapsulating Security Payload             [RFC5840]
  'ROHC': 142 // Robust Header Compression                           [RFC5858]
}

type IP_PART2 = {
  '0': 'HOPOPT'
  '1': 'ICMP'
  '2': 'IGMP'
  '3': 'GGP'
  '4': 'IPV4'
  '5': 'ST'
  '6': 'TCP'
  '7': 'CBT'
  '8': 'EGP'
  '9': 'IGP'
  '10': 'BBN-RCC-MON'
  '11': 'NVP-II'
  '12': 'PUP'
  '13': 'ARGUS'
  '14': 'EMCON'
  '15': 'XNET'
  '16': 'CHAOS'
  '17': 'UDP'
  '18': 'MUX'
  '19': 'DCN-MEAS'
  '20': 'HMP'
  '21': 'PRM'
  '22': 'XNS-IDP'
  '23': 'TRUNK-1'
  '24': 'TRUNK-2'
  '25': 'LEAF-1'
  '26': 'LEAF-2'
  '27': 'RDP'
  '28': 'IRTP'
  '29': 'ISO-TP4'
  '30': 'NETBLT'
  '31': 'MFE-NSP'
  '32': 'MERIT-INP'
  '33': 'DCCP'
  '34': '3PC'
  '35': 'IDPR'
  '36': 'XTP'
  '37': 'DDP'
  '38': 'IDPR-CMTP'
  '39': 'TP++'
  '40': 'IL'
  '41': 'IPV6'
  '42': 'SDRP'
  '43': 'IPV6-ROUTE'
  '44': 'IPV6-FRAG'
  '45': 'IDRP'
  '46': 'RSVP'
  '47': 'GRE'
  '48': 'DSR'
  '49': 'BNA'
  '50': 'ESP'
  '51': 'AH'
  '52': 'I-NLSP'
  '53': 'SWIPE'
  '54': 'NARP'
  '55': 'MOBILE'
  '56': 'TLSP'
  '57': 'SKIP'
  '58': 'ICMPV6'
  '59': 'IPV6-NONXT'
  '60': 'IPV6-OPTS'
  '62': 'CFTP'
  '64': 'SAT-EXPAK'
  '65': 'KRYPTOLAN'
  '66': 'RVD'
  '67': 'IPPC'
  '69': 'SAT-MON'
  '70': 'VISA'
  '71': 'IPCV'
  '72': 'CPNX'
  '73': 'CPHB'
  '74': 'WSN'
  '75': 'PVP'
  '76': 'BR-SAT-MON'
  '77': 'SUN-ND'
  '78': 'WB-MON'
  '79': 'WB-EXPAK'
  '80': 'ISO-IP'
  '81': 'VMTP'
  '82': 'SECURE-VMTP'
  '83': 'VINES'
  '84': 'TTP'
  '84': 'IPTM'
  '85': 'NSFNET-IGP'
  '86': 'DGP'
  '87': 'TCF'
  '88': 'EIGRP'
  '89': 'OSPFIGP'
  '90': 'SPRITE-RPC'
  '91': 'LARP'
  '92': 'MTP'
  '93': 'AX.25'
  '94': 'IPIP'
  '95': 'MICP'
  '96': 'SCC-SP'
  '97': 'ETHERIP'
  '98': 'ENCAP'
  '100': 'GMTP'
  '101': 'IFMP'
  '102': 'PNNI'
  '103': 'PIM'
  '104': 'ARIS'
  '105': 'SCPS'
  '106': 'QNX'
  '107': 'A/N'
  '108': 'IPCOMP'
  '109': 'SNP'
  '110': 'COMPAQ-PEER'
  '111': 'IPX-IN-IP'
  '112': 'VRRP'
  '113': 'PGM'
  '115': 'L2TP'
  '116': 'DDX'
  '117': 'IATP'
  '118': 'STP'
  '119': 'SRP'
  '120': 'UTI'
  '121': 'SMP'
  '122': 'SM'
  '123': 'PTP'
  '124': 'ISIS'
  '125': 'FIRE'
  '126': 'CRTP'
  '127': 'CRUDP'
  '128': 'SSCOPMCE'
  '129': 'IPLT'
  '130': 'SPS'
  '131': 'PIPE'
  '132': 'SCTP'
  '133': 'FC'
  '134': 'RSVP-E2E-IGNORE'
  '135': 'MOBILITY HEADER'
  '136': 'UDPLITE'
  '137': 'MPLS-IN-IP'
  '138': 'MANET'
  '139': 'HIP'
  '140': 'SHIM6'
  '141': 'WESP'
  '142': 'ROHC'
}
