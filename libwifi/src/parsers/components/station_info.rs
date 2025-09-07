#![allow(dead_code)]
use nom::{
    IResult, Parser,
    bytes::complete::take,
    error::{Error, ErrorKind},
    number::complete::u8 as get_u8,
};

use crate::{
    bit_utils::{get_bit, get_bits},
    frame::components::{
        AudioDevices, Cameras, Category, ChannelSwitchAnnouncment, ChannelSwitchMode, Computers,
        Displays, DockingDevices, ExtendedCapabilities, GamingDevices, HTCapabilities,
        HTInformation, InputDevices, MultimediaDevices, MultipleBSSID, NetworkInfrastructure,
        PrintersEtAl, RsnAkmSuite, RsnCipherSuite, RsnInformation, StationInfo, Storage,
        SupportedRate, Telephone, VHTCapabilities, VendorSpecificInfo, WpaAkmSuite, WpaCipherSuite,
        WpaInformation, WpsInformation, WpsSetupState,
    },
};

/// Parse variable length and variable field information.
/// The general structure of the data looks like this:
///
/// 1 byte: Element id
/// 1 byte: Element length (up to 255 bytes)
/// $element_length bytes: Element data
///
/// This format is only used in management frames.
///
/// There might be multiple elements with the same element id,
/// which is why StationInfo uses a Vec instead of BTreeMap as a data structure.
pub fn parse_station_info(mut input: &[u8]) -> IResult<&[u8], StationInfo> {
    let mut station_info = StationInfo::default();

    let mut element_id;
    let mut length;
    let mut data;
    loop {
        (input, (element_id, length)) = (get_u8, get_u8).parse(input)?;
        (input, data) = take(length)(input)?;
        if !data.is_empty() {
            match element_id {
                0 => {
                    let ssid = String::from_utf8_lossy(data).to_string();
                    station_info.ssid = Some(ssid);
                    station_info.ssid_length = Some(length as usize);
                    // if ssid is not utf8, can use the raw data.
                    station_info.ssid_raw = Some(data[..length as usize].to_vec());
                }
                1 => station_info.supported_rates = parse_supported_rates(data),
                3 => station_info.ds_parameter_set = Some(data[0]),
                5 => station_info.tim = Some(data.to_vec()),
                6 => {
                    station_info.ibss_parameter_set = if data.len() >= 2 {
                        Some(u16::from_le_bytes([data[0], data[1]]))
                    } else {
                        None
                    }
                }
                7 => station_info.country_info = Some(data.to_vec()),
                32 => station_info.power_constraint = Some(data[0]),
                37 => station_info.channel_switch = parse_channel_switch(data),
                45 => station_info.ht_capabilities = parse_ht_capabilities(data),
                48 => {
                    if let Ok(rsn_info) = parse_rsn_information(data) {
                        station_info.rsn_information = Some(rsn_info)
                    }
                }
                50 => station_info.extended_supported_rates = Some(parse_supported_rates(data)),
                61 => {
                    if let Ok(ht_info) = parse_ht_information(data) {
                        station_info.ht_information = Some(ht_info)
                    }
                }
                71 => {
                    if let Ok(multiple_bssid) = parse_multiple_bssid(data) {
                        station_info.multiple_bssid = Some(multiple_bssid)
                    }
                }
                127 => station_info.extended_capabilities = parse_extended_capabilities(data).ok(),
                191 => station_info.vht_capabilities = parse_vht_capabilities(data),
                221 => {
                    // Vendor-specific tag
                    if data.len() >= 4 {
                        // Minimum length for OUI and OUI Type
                        let oui = [data[0], data[1], data[2]];
                        let oui_type = data[3];
                        let vendor_data = data[4..].to_vec();

                        if oui == [0x00, 0x50, 0xf2] && oui_type == 1 {
                            let wpa_info = match parse_wpa_information(&vendor_data) {
                                Ok(wpa_info) => wpa_info,
                                Err(_) => {
                                    let nom_error = Error::new(input, ErrorKind::Fail);
                                    return Err(nom::Err::Error(nom_error));
                                }
                            };
                            // Specific parsing for WPA Information Element
                            station_info.wpa_info = Some(wpa_info);
                        } else if oui == [0x00, 0x50, 0xf2] && oui_type == 4 {
                            // Specific parsing for WPS Information Element
                            station_info.wps_info = parse_wps_information(&vendor_data).ok();
                        } else {
                            let vendor_specific_info = VendorSpecificInfo {
                                element_id,
                                length,
                                oui,
                                oui_type,
                                data: vendor_data,
                            };
                            station_info.vendor_specific.push(vendor_specific_info);
                        }
                    }
                }
                255 => {
                    let ext_element_id = data[0];
                    match ext_element_id {
                        35 => {
                            station_info.he_capabilities = Some(data.to_vec());
                        }
                        _ => { // TODO: implement parsing for other extended element ids
                        }
                    }
                }
                _ => {
                    station_info.data.push((element_id, data.to_vec()));
                }
            };

            if input.len() <= 4 {
                break;
            }
        }
    }

    Ok((input, station_info))
}

fn parse_wpa_information(data: &[u8]) -> Result<WpaInformation, &'static str> {
    if data.len() < 10 {
        return Err("WPA Information data too short");
    }

    let version = u16::from_le_bytes([data[0], data[1]]);
    if version != 1 {
        return Err("Unsupported WPA version");
    }

    let multicast_cipher_suite = parse_cipher_suite(&data[2..6]);
    let unicast_cipher_suite_count = u16::from_le_bytes([data[6], data[7]]) as usize;
    let mut offset = 8;

    if data.len() < offset + 4 * unicast_cipher_suite_count {
        return Err("WPA Information data too short for unicast cipher suites");
    }

    let mut unicast_cipher_suites = Vec::new();
    for _ in 0..unicast_cipher_suite_count {
        let cipher_suite = parse_cipher_suite(&data[offset..offset + 4]);
        unicast_cipher_suites.push(cipher_suite);
        offset += 4;
    }

    if data.len() < offset + 2 {
        return Err("WPA Information data too short for AKM suite count");
    }

    let akm_suite_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if data.len() < offset + 4 * akm_suite_count {
        return Err("WPA Information data too short for AKM suites");
    }

    let mut akm_suites = Vec::new();
    for _ in 0..akm_suite_count {
        let akm_suite = parse_wpa_akm_suite(&data[offset..offset + 4]);
        akm_suites.push(akm_suite);
        offset += 4;
    }

    Ok(WpaInformation {
        version,
        multicast_cipher_suite,
        unicast_cipher_suites,
        akm_suites,
    })
}

fn parse_extended_capabilities(data: &[u8]) -> Result<ExtendedCapabilities, &'static str> {
    if data.is_empty() {
        return Err("Extended capabilities is empty");
    }

    Ok(ExtendedCapabilities {
        bss_coexistence_management_support: get_bit(data, 0),
        glk: get_bit(data, 1),
        extended_channel_switching: get_bit(data, 2),
        glk_gcr: get_bit(data, 3),
        psmp_capability: get_bit(data, 4),
        //reserved5: get_bit(data,5),
        s_psmp_capability: get_bit(data, 6),
        event: get_bit(data, 7),
        diagnostics: get_bit(data, 8),
        multicast_diagnostics: get_bit(data, 9),
        location_tracking: get_bit(data, 10),
        fms: get_bit(data, 11),
        proxy_arp_service: get_bit(data, 12),
        collocated_interference_reporting: get_bit(data, 13),
        civic_location: get_bit(data, 14),
        geospatial_location: get_bit(data, 15),
        tfs: get_bit(data, 16),
        wnm_sleep_mode: get_bit(data, 17),
        tim_broadcast: get_bit(data, 18),
        bss_transition: get_bit(data, 19),
        qos_traffic_capability: get_bit(data, 20),
        ac_station_count: get_bit(data, 21),
        multiple_bssid: get_bit(data, 22),
        timing_measurement: get_bit(data, 23),
        channel_usage: get_bit(data, 24),
        ssid_list: get_bit(data, 25),
        dms: get_bit(data, 26),
        utc_tsf_offset: get_bit(data, 27),
        tpu_buffer_sta_support: get_bit(data, 28),
        tdls_peer_psm_support: get_bit(data, 29),
        tdls_channel_switching: get_bit(data, 30),
        internetworking: get_bit(data, 31),
        qos_map: get_bit(data, 32),
        ebr: get_bit(data, 33),
        sspn_interface: get_bit(data, 34),
        //reserved35: get_bit(data,35),
        msgcf_capability: get_bit(data, 36),
        tdls_support: get_bit(data, 37),
        tdls_prohibited: get_bit(data, 38),
        tdls_channel_switching_prohibited: get_bit(data, 39),
        reject_unadmitted_frame: get_bit(data, 40),
        service_interval_granularity: get_bits(data, 41, 43),
        identifier_location: get_bit(data, 44),
        uapsd_coexistence: get_bit(data, 45),
        wnm_notification: get_bit(data, 46),
        qab_capability: get_bit(data, 47),
        utf8_ssid: get_bit(data, 48),
        qmf_activated: get_bit(data, 49),
        qmf_reconfiguration_activated: get_bit(data, 50),
        robust_av_streaming: get_bit(data, 51),
        advanced_gcr: get_bit(data, 52),
        mesh_gcr: get_bit(data, 53),
        scs: get_bit(data, 54),
        qload_report: get_bit(data, 55),
        alternate_edca: get_bit(data, 56),
        unprotected_txop_negotiation: get_bit(data, 57),
        protected_txop_negotiation: get_bit(data, 58),
        //reserved59: get_bit(data,59),
        protected_qload_report: get_bit(data, 60),
        tdls_wider_bandwidth: get_bit(data, 61),
        operating_mode_notification: get_bit(data, 62),
        max_number_of_msdus_in_amsdu: get_bits(data, 63, 64),
        channel_schedule_management: get_bit(data, 65),
        geodatabase_inband_enabling_signal: get_bit(data, 66),
        network_channel_control: get_bit(data, 67),
        white_space_map: get_bit(data, 68),
        channel_availability_query: get_bit(data, 69),
        fine_timing_measurement_responder: get_bit(data, 70),
        fine_timing_measurement_initiator: get_bit(data, 71),
        fils_capability: get_bit(data, 72),
        extended_spectrum_management_capable: get_bit(data, 73),
        future_channel_guidance: get_bit(data, 74),
        pad: get_bit(data, 75),
        //reserved76: get_bit(data,76),
        twt_requester_support: get_bit(data, 77),
        twt_responder_support: get_bit(data, 78),
        obss_narrow_bandwidth_ru_in_odfma_tolerance_support: get_bit(data, 79),
        complete_list_of_nontxbssid_profiles: get_bit(data, 80),
        sae_password_in_use: get_bit(data, 81),
        sae_password_used_exclusively: get_bit(data, 82),
        enhanced_multibssid_advertisement_support: get_bit(data, 83),
        beacon_protection_enabled: get_bit(data, 84),
        mirrored_scs: get_bit(data, 85),
        oct: get_bit(data, 86),
        local_mac_address_policy: get_bit(data, 87),
        //reserved88: get_bit(data,88),
        twt_parameters_range_support: get_bit(data, 89),
    })
}

pub fn parse_ht_capabilities(data: &[u8]) -> Option<HTCapabilities> {
    if data.len() < 2 {
        return None;
    }
    let data = [data[0], data[1]];
    let bits = u16::from_le_bytes(data);

    macro_rules! bit {
        ($b:expr) => {
            bits & (1 << $b) != 0
        };
    }

    Some(HTCapabilities {
        ldpc_coding_capability: bit!(0),
        supported_channel_width: bit!(1),
        sm_power_save: (((bits >> 2) & 0x3) as u8).into(),
        green_field: bit!(4),
        short_gi_20_mhz: bit!(5),
        short_gi_40_mhz: bit!(6),
        tx_stbc: bit!(7),
        rx_stbc: (((bits >> 8) & 0x3) as u8).into(),
        delayed_block_ack: bit!(10),
        max_amsdu_length: bit!(11),
        dsss_support: bit!(12),
        psmp_support: bit!(13),
        forty_mhz_intolerant: bit!(14),
        l_sig_tx_op_protection: bit!(15),
    })
}

fn parse_ht_information(data: &[u8]) -> Result<HTInformation, &'static str> {
    if data.len() < 2 {
        return Err("HT Information data too short");
    }
    let secondary_channel_offset_raw = data[1] & 0b11;
    let supported_channel_width = (data[1] & 0b100) > 0;

    Ok(HTInformation {
        primary_channel: data[0],
        secondary_channel_offset: secondary_channel_offset_raw.into(),
        supported_channel_width,
        other_data: data[2..].to_vec(),
    })
}

fn parse_vht_capabilities(data: &[u8]) -> Option<VHTCapabilities> {
    if data.is_empty() {
        return None;
    }

    let maximum_mpdu_length = data[0] & 0b11;

    let rx_ldpc = (data[0] & 1 << 4) > 0;

    let short_gi_80mhz = (data[0] & (1 << 5)) > 0;
    let short_gi_160mhz = (data[0] & (1 << 6)) > 0;

    Some(VHTCapabilities {
        maximum_mpdu_length,
        rx_ldpc,
        short_gi_80mhz,
        short_gi_160mhz,
        data: data.to_vec(),
    })
}

fn parse_multiple_bssid(data: &[u8]) -> Result<MultipleBSSID, &'static str> {
    // shortest possible length is maxBSSIDIndicator u8
    if data.is_empty() {
        return Err("Multiple BSSID data too short");
    }
    Ok(MultipleBSSID {
        max_bssid_indicator: data[0],
        other_data: data[1..].to_vec(),
    })
}

fn parse_wps_information(data: &[u8]) -> Result<WpsInformation, &'static str> {
    let mut wps_info = WpsInformation::default();
    let mut offset = 0;

    while offset < data.len() {
        if offset + 4 > data.len() {
            return Err("Invalid WPS data length");
        }

        let element_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let element_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + element_length > data.len() {
            return Err("Invalid WPS data length for element");
        }

        match element_type {
            0x1057 => {
                wps_info.setup_state = match data[offset] {
                    0x01 => WpsSetupState::NotConfigured,
                    0x02 => WpsSetupState::Configured,
                    _ => return Err("Invalid WPS Setup State"),
                };
            }
            0x1021 => {
                wps_info.manufacturer =
                    parse_string_from_bytes(&data[offset..offset + element_length])?;
            }
            0x1023 => {
                wps_info.model = parse_string_from_bytes(&data[offset..offset + element_length])?;
            }
            0x1024 => {
                wps_info.model_number =
                    parse_string_from_bytes(&data[offset..offset + element_length])?;
            }
            0x1042 => {
                wps_info.serial_number =
                    parse_string_from_bytes(&data[offset..offset + element_length])?;
            }
            0x1054 => {
                let device_type_data = data[offset..offset + element_length].to_vec();
                if device_type_data.len() >= 8 {
                    let oui = device_type_data[2..6].to_vec();
                    if oui == [0x00, 0x50, 0xf2, 0x04] {
                        let category = device_type_data[0..2].to_vec();
                        let subcategory = device_type_data[6..8].to_vec();
                        if let Some(cat) = bytes_to_category(category, subcategory) {
                            wps_info.primary_device_type = cat.to_string();
                        } else {
                            "".clone_into(&mut wps_info.primary_device_type);
                        }
                    }
                } else {
                    "".clone_into(&mut wps_info.primary_device_type);
                }
            }
            0x1011 => {
                wps_info.device_name =
                    parse_string_from_bytes(&data[offset..offset + element_length])?;
            }
            _ => {} // Unknown or unhandled type
        }

        offset += element_length;
    }

    Ok(wps_info)
}

fn bytes_to_category(catbytes: Vec<u8>, subbytes: Vec<u8>) -> Option<Category> {
    if catbytes.len() == 2 {
        let value = (u16::from(catbytes[0]) << 8) | u16::from(catbytes[1]);
        let subvalue = (u16::from(subbytes[0]) << 8) | u16::from(subbytes[1]);
        match value {
            0x0001 => match subvalue {
                0x0001 => Some(Category::Computer(Computers::PC)),
                0x0002 => Some(Category::Computer(Computers::Server)),
                0x0003 => Some(Category::Computer(Computers::MediaCenter)),
                0x0004 => Some(Category::Computer(Computers::UltraMobilePC)),
                0x0005 => Some(Category::Computer(Computers::Notebook)),
                0x0006 => Some(Category::Computer(Computers::Desktop)),
                0x0007 => Some(Category::Computer(Computers::MID)),
                0x0008 => Some(Category::Computer(Computers::Netbook)),
                0x0009 => Some(Category::Computer(Computers::Tablet)),
                0x000a => Some(Category::Computer(Computers::Ultrabook)),
                _ => None,
            },
            0x0002 => match subvalue {
                0x0001 => Some(Category::InputDevice(InputDevices::Keyboard)),
                0x0002 => Some(Category::InputDevice(InputDevices::Mouse)),
                0x0003 => Some(Category::InputDevice(InputDevices::Joystick)),
                0x0004 => Some(Category::InputDevice(InputDevices::Trackball)),
                0x0005 => Some(Category::InputDevice(InputDevices::GamingController)),
                0x0006 => Some(Category::InputDevice(InputDevices::Remote)),
                0x0007 => Some(Category::InputDevice(InputDevices::Touchscreen)),
                0x0008 => Some(Category::InputDevice(InputDevices::BiometricReader)),
                0x0009 => Some(Category::InputDevice(InputDevices::BarcodeReader)),
                _ => None,
            },
            0x0003 => match subvalue {
                0x0001 => Some(Category::PrintersScannersFaxCopier(PrintersEtAl::Printer)),
                0x0002 => Some(Category::PrintersScannersFaxCopier(PrintersEtAl::Scanner)),
                0x0003 => Some(Category::PrintersScannersFaxCopier(PrintersEtAl::Fax)),
                0x0004 => Some(Category::PrintersScannersFaxCopier(PrintersEtAl::Copier)),
                0x0005 => Some(Category::PrintersScannersFaxCopier(PrintersEtAl::AllInOne)),
                _ => None,
            },
            0x0004 => match subvalue {
                0x0001 => Some(Category::Camera(Cameras::DigitalCamera)),
                0x0002 => Some(Category::Camera(Cameras::VideoCamera)),
                0x0003 => Some(Category::Camera(Cameras::Webcam)),
                0x0004 => Some(Category::Camera(Cameras::SecurityCamera)),
                _ => None,
            },
            0x0005 => Some(Category::Storage(Storage::NAS)),
            0x0006 => match subvalue {
                0x0001 => Some(Category::NetworkInfrastructure(NetworkInfrastructure::AP)),
                0x0002 => Some(Category::NetworkInfrastructure(
                    NetworkInfrastructure::Router,
                )),
                0x0003 => Some(Category::NetworkInfrastructure(
                    NetworkInfrastructure::Switch,
                )),
                0x0004 => Some(Category::NetworkInfrastructure(
                    NetworkInfrastructure::Gateway,
                )),
                0x0005 => Some(Category::NetworkInfrastructure(
                    NetworkInfrastructure::Bridge,
                )),
                _ => None,
            },
            0x0007 => match subvalue {
                0x0001 => Some(Category::Displays(Displays::Television)),
                0x0002 => Some(Category::Displays(Displays::ElectronicPictureFrame)),
                0x0003 => Some(Category::Displays(Displays::Projector)),
                0x0004 => Some(Category::Displays(Displays::Monitor)),
                _ => None,
            },
            0x0008 => match subvalue {
                0x0001 => Some(Category::MultimediaDevices(MultimediaDevices::DAR)),
                0x0002 => Some(Category::MultimediaDevices(MultimediaDevices::PVR)),
                0x0003 => Some(Category::MultimediaDevices(MultimediaDevices::MCX)),
                0x0004 => Some(Category::MultimediaDevices(MultimediaDevices::SetTopBox)),
                0x0005 => Some(Category::MultimediaDevices(MultimediaDevices::MediaServer)),
                0x0006 => Some(Category::MultimediaDevices(
                    MultimediaDevices::ProtableVideoPlayer,
                )),
                _ => None,
            },
            0x0009 => match subvalue {
                0x0001 => Some(Category::GamingDevices(GamingDevices::Xbox)),
                0x0002 => Some(Category::GamingDevices(GamingDevices::Xbox360)),
                0x0003 => Some(Category::GamingDevices(GamingDevices::Playstation)),
                0x0004 => Some(Category::GamingDevices(GamingDevices::GameConsole)),
                0x0005 => Some(Category::GamingDevices(GamingDevices::PortableGamingDevice)),
                _ => None,
            },
            0x000a => match subvalue {
                0x0001 => Some(Category::Telephone(Telephone::WindowsMobile)),
                0x0002 => Some(Category::Telephone(Telephone::PhoneSingleMode)),
                0x0003 => Some(Category::Telephone(Telephone::PhoneDualMode)),
                0x0004 => Some(Category::Telephone(Telephone::SmartphoneSingleMode)),
                0x0005 => Some(Category::Telephone(Telephone::SmartphoneDualMode)),
                _ => None,
            },
            0x000b => match subvalue {
                0x0001 => Some(Category::AudioDevices(AudioDevices::AutioTunerReceiver)),
                0x0002 => Some(Category::AudioDevices(AudioDevices::Speakers)),
                0x0003 => Some(Category::AudioDevices(AudioDevices::PortableMusicPlayer)),
                0x0004 => Some(Category::AudioDevices(AudioDevices::Headset)),
                0x0005 => Some(Category::AudioDevices(AudioDevices::Headphones)),
                0x0006 => Some(Category::AudioDevices(AudioDevices::Microphone)),
                0x0007 => Some(Category::AudioDevices(AudioDevices::HomeTheaterSystems)),
                _ => None,
            },
            0x000c => match subvalue {
                0x0001 => Some(Category::DockingDevices(
                    DockingDevices::ComputerDockingStation,
                )),
                0x0002 => Some(Category::DockingDevices(DockingDevices::MediaKiosk)),
                _ => None,
            },
            _ => None,
        }
    } else {
        None
    }
}

fn bytes_to_subcategory(category: &Category, bytes: Vec<u8>) -> Option<String> {
    if bytes.len() == 2 {
        let value = (u16::from(bytes[0]) << 8) | u16::from(bytes[1]);
        match category {
            Category::Computer(_) => match value {
                0x0001 => Some(Computers::PC.to_string()),
                _ => None,
            },
            _ => None,
        }
    } else {
        None
    }
}

fn parse_device_type_data(device_type_data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if device_type_data.len() >= 8 {
        let category = device_type_data[0..2].to_vec();
        let oui = device_type_data[2..6].to_vec();
        let subcategory = device_type_data[6..8].to_vec();

        Some((category, oui, subcategory))
    } else {
        None
    }
}

fn parse_string_from_bytes(data: &[u8]) -> Result<String, &'static str> {
    match std::str::from_utf8(data) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err("Invalid UTF-8 string"),
    }
}

pub fn parse_rsn_information(data: &[u8]) -> Result<RsnInformation, &'static str> {
    if data.len() < 10 {
        return Err("RSN Information data too short");
    }

    let version = u16::from_ne_bytes([data[0], data[1]]);
    if version != 1 {
        return Err("Unsupported RSN version");
    }

    let group_cipher_suite = parse_group_cipher_suite(&data[2..6]);
    let pairwise_cipher_suite_count = u16::from_ne_bytes([data[6], data[7]]) as usize;
    let mut offset = 8;

    let mut pairwise_cipher_suites = Vec::new();
    for _ in 0..pairwise_cipher_suite_count {
        if data.len() < offset + 4 {
            return Err("Pairwise cipher suite data field too short");
        }
        let suite = parse_pairwise_cipher_suite(&data[offset..offset + 4]);
        pairwise_cipher_suites.push(suite);
        offset += 4;
    }

    if offset + 1 >= data.len() {
        return Err("Data field to short");
    }
    let akm_suite_count = u16::from_ne_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let mut akm_suites = Vec::new();
    for _ in 0..akm_suite_count {
        if data.len() < offset + 4 {
            return Err("AKM suite data field too short");
        }
        let suite = parse_akm_suite(&data[offset..offset + 4]);
        akm_suites.push(suite);
        offset += 4;
    }

    if data.len() >= offset + 2 {
        let rsn_capabilities = u16::from_ne_bytes([data[offset], data[offset + 1]]);

        let pre_auth = (rsn_capabilities & (1 << 0)) != 0;
        let no_pairwise = (rsn_capabilities & (1 << 1)) != 0;
        let ptksa_replay_counter = ((rsn_capabilities >> 2) & 0x03) as u8; // Extract 2 bits starting at position 2
        let gtksa_replay_counter = ((rsn_capabilities >> 4) & 0x03) as u8; // Extract 2 bits starting at position 4
        let mfp_required = (rsn_capabilities & (1 << 6)) != 0;
        let mfp_capable = (rsn_capabilities & (1 << 7)) != 0;
        let joint_multi_band_rsna = (rsn_capabilities & (1 << 8)) != 0;
        let peerkey_enabled = (rsn_capabilities & (1 << 9)) != 0;
        let extended_key_id = (rsn_capabilities & (1 << 13)) != 0;
        let ocvc = (rsn_capabilities & (1 << 14)) != 0;

        Ok(RsnInformation {
            version,
            group_cipher_suite,
            pairwise_cipher_suites,
            akm_suites,
            pre_auth,
            no_pairwise,
            ptksa_replay_counter,
            gtksa_replay_counter,
            mfp_required,
            mfp_capable,
            joint_multi_band_rsna,
            peerkey_enabled,
            extended_key_id,
            ocvc,
        })
    } else {
        Err("RSN Information data too short for RSN Capabilities")
    }
}

pub fn parse_channel_switch(data: &[u8]) -> Option<ChannelSwitchAnnouncment> {
    if data.len() < 3 {
        return None;
    }

    let mode = ChannelSwitchMode::from_u8(data[0]);
    let new_channel = data[1];
    let count = data[2];

    Some(ChannelSwitchAnnouncment {
        mode,
        new_channel,
        count,
    })
}

fn parse_cipher_suite(data: &[u8]) -> WpaCipherSuite {
    match data {
        [0x00, 0x50, 0xF2, 0x01] => WpaCipherSuite::Wep40,
        [0x00, 0x50, 0xF2, 0x05] => WpaCipherSuite::Wep104,
        [0x00, 0x50, 0xF2, 0x02] => WpaCipherSuite::Tkip,
        [0x00, 0x50, 0xF2, 0x04] => WpaCipherSuite::Ccmp,
        _ => WpaCipherSuite::Unknown(data.to_vec()),
    }
}

fn parse_wpa_akm_suite(data: &[u8]) -> WpaAkmSuite {
    match data {
        [0x00, 0x50, 0xF2, 0x01] => WpaAkmSuite::Psk,
        [0x00, 0x50, 0xF2, 0x02] => WpaAkmSuite::Eap,
        _ => WpaAkmSuite::Unknown(data.to_vec()),
    }
}

fn parse_group_cipher_suite(data: &[u8]) -> RsnCipherSuite {
    match data {
        [0x00, 0x0F, 0xAC, 0x00] => RsnCipherSuite::None,
        [0x00, 0x0F, 0xAC, 0x01] => RsnCipherSuite::WEP,
        [0x00, 0x0F, 0xAC, 0x02] => RsnCipherSuite::TKIP,
        [0x00, 0x0F, 0xAC, 0x03] => RsnCipherSuite::WRAP,
        [0x00, 0x0F, 0xAC, 0x04] => RsnCipherSuite::CCMP,
        [0x00, 0x0F, 0xAC, 0x05] => RsnCipherSuite::WEP104,
        _ => RsnCipherSuite::Unknown(data.to_vec()),
    }
}

fn parse_pairwise_cipher_suite(data: &[u8]) -> RsnCipherSuite {
    match data {
        [0x00, 0x0F, 0xAC, 0x00] => RsnCipherSuite::None,
        [0x00, 0x0F, 0xAC, 0x01] => RsnCipherSuite::WEP,
        [0x00, 0x0F, 0xAC, 0x02] => RsnCipherSuite::TKIP,
        [0x00, 0x0F, 0xAC, 0x03] => RsnCipherSuite::WRAP,
        [0x00, 0x0F, 0xAC, 0x04] => RsnCipherSuite::CCMP,
        [0x00, 0x0F, 0xAC, 0x05] => RsnCipherSuite::WEP104,
        _ => RsnCipherSuite::Unknown(data.to_vec()),
    }
}

fn parse_akm_suite(data: &[u8]) -> RsnAkmSuite {
    match data {
        [0x00, 0x0F, 0xAC, 0x01] => RsnAkmSuite::EAP,
        [0x00, 0x0F, 0xAC, 0x02] => RsnAkmSuite::PSK,
        [0x00, 0x0F, 0xAC, 0x03] => RsnAkmSuite::EAPFT,
        [0x00, 0x0F, 0xAC, 0x04] => RsnAkmSuite::PSKFT,
        [0x00, 0x0F, 0xAC, 0x05] => RsnAkmSuite::EAP256,
        [0x00, 0x0F, 0xAC, 0x06] => RsnAkmSuite::PSK256,
        [0x00, 0x0F, 0xAC, 0x08] => RsnAkmSuite::SAE,
        [0x00, 0x0F, 0xAC, 0x0b] => RsnAkmSuite::SUITEBEAP256,
        _ => RsnAkmSuite::Unknown(data.to_vec()),
    }
}

fn parse_supported_rates(input: &[u8]) -> Vec<SupportedRate> {
    input
        .iter()
        .map(|&data| {
            let rate = (data & 0x7F) as f32 / 2.0;
            let mandatory = (data & 0x80) != 0;
            SupportedRate { mandatory, rate }
        })
        .collect()
}
