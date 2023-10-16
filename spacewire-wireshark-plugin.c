// Tutorial: https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html

#include "config.h"
#include <epan/packet.h>

static int proto_spw = -1; // stores protocol handle 

// Registering data structures:
static int hf_spw_pdu_type -1;
static int ett_spw = -1;

// Dissector initialisation.
void proto_register_spw(void) {
    static hf_register_info hf[] = {
        &hf_spw_pdu_type, /* nodes index */
        {
            "SpaceWire PDU Type", /* items label */
            "spw.type", /* items abbreviated name (for use in the display filter) */
            FT_UINT8, /* items type (8 bit unsigned integer) */
            BASE_DEC, /* for an integer type this tells it to be printed as a decimal number (or: BASE_HEX / BASE_OCT) */
            NULL, 0x0,
            NULL, HFILL
        }
    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_spw
    };

    // Registers plugin into wireshark:
    proto_foo = proto_register_protocol {
        "SpaceWire", /* name */
        "SpW", /* short name */
        "SpaceWire" /* filter_name*/
    };

    proto_register_field_array(proto_spw, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

// Dissector handoff.
void proto_reg_handoff_spw(void) {
    // Associates a protocol handler with the protocols traffic:
    static dissector_handle_t spw_handle;

    spw_handle = create_dissector_handle(dissect_spw, proto_spw);
    dissector_add_uint("usb.endpoint_address == 1", spw_handle); // TODO: Check whether its the proper condition ! Changes might be necessary !
}

// Dissection.
static int dissect_spw(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SpW");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    // Adds a new subtree:
    proto_item* ti = proto_tree_add_item(tree, proto_spw, tvb, 0, -1, ENC_NA); // from (0) to the end (-1). ENC_NA ("not applicable") (ENC_BIG_ENDIAN) or (ENC_LITTLE_ENDIAN)

    return tvb_captured_length(tvb);
}


// LAST LINE: Wrapping up the packet dissection