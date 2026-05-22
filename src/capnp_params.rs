//! Direct capnp struct field filling for RegisterConnection params.
//!
//! Uses capnp's layout API to write fields directly into the request's
//! params builder — no separate message, no set_as() nesting.
//!
//! Schema (from tunnelrpc.capnp):
//!
//! registerConnection @0 (
//!   auth      @0 :TunnelAuth,       # ptr[0]
//!   tunnelId  @1 :Data,             # ptr[1]
//!   connIndex @2 :UInt8,            # data[0] byte 0
//!   options   @3 :ConnectionOptions # ptr[2]
//! )
//!
//! struct TunnelAuth {                DataSize=0  PointerCount=2
//!   accountTag    @0 :Text           # ptr[0]
//!   tunnelSecret  @1 :Data           # ptr[1]
//! }
//!
//! struct ConnectionOptions {         DataSize=8  PointerCount=2
//!   client              @0 :ClientInfo    # ptr[0]
//!   originLocalIp       @1 :Data          # ptr[1]  (leave null)
//!   replaceExisting     @2 :Bool          # data[0] bit 8
//!   compressionQuality  @3 :UInt8         # data[0] byte 3
//!   numPreviousAttempts @4 :UInt8         # data[0] byte 4
//! }
//!
//! struct ClientInfo {                DataSize=0  PointerCount=4
//!   clientId  @0 :Data              # ptr[0]
//!   features  @1 :List(Text)        # ptr[1]
//!   version   @2 :Text              # ptr[2]
//!   arch      @3 :Text              # ptr[3]
//! }

use capnp::private::layout::{ElementSize, StructSize};
use capnp::any_pointer;
use anyhow::Result;

// Struct sizes from generated Go code (ObjectSize fields)
const AUTH_SIZE:    StructSize = StructSize { data: 0, pointers: 2 };
const OPTIONS_SIZE: StructSize = StructSize { data: 1, pointers: 2 };
const CLIENT_SIZE:  StructSize = StructSize { data: 0, pointers: 4 };
// registerConnection params struct: DataSize=8(1 word), PointerCount=3
const PARAMS_SIZE:  StructSize = StructSize { data: 1, pointers: 3 };

/// Fill a registerConnection params AnyPointer builder with all fields.
///
/// `params` is the `request.get()` result from a capnp-rpc Request.
pub fn fill_register_connection(
    mut params: any_pointer::Builder<'_>,
    account_tag: &str,
    tunnel_secret: &[u8],
    tunnel_id: &[u8; 16],
    conn_index: u8,
    client_id: &[u8; 16],
    version: &str,
    arch: &str,
    features: &[&str],
) -> Result<()> {
    // Initialise the root params struct
    let mut p = params.init_as_struct(PARAMS_SIZE);

    // connIndex @2 :UInt8  → data[0] byte 0
    // (field index 2 but stored at data offset 0 for UInt8 in capnp)
    p.set_data_field::<u8>(0, conn_index);

    // auth @0 :TunnelAuth  → ptr[0]
    {
        let mut auth = p.reborrow().get_pointer_field(0).init_struct(AUTH_SIZE);
        // accountTag @0 :Text → ptr[0]
        auth.reborrow().get_pointer_field(0).set_text(account_tag.into());
        // tunnelSecret @1 :Data → ptr[1]
        auth.get_pointer_field(1).set_data(tunnel_secret);
    }

    // tunnelId @1 :Data  → ptr[1]
    p.reborrow().get_pointer_field(1).set_data(tunnel_id);

    // options @3 :ConnectionOptions → ptr[2]
    {
        let mut opts = p.reborrow().get_pointer_field(2).init_struct(OPTIONS_SIZE);
        // numPreviousAttempts @4 :UInt8 → data[0] byte 4
        opts.set_data_field::<u8>(4, 0u8);

        // client @0 :ClientInfo → ptr[0]
        let mut client = opts.reborrow().get_pointer_field(0).init_struct(CLIENT_SIZE);

        // clientId @0 :Data → ptr[0]
        client.reborrow().get_pointer_field(0).set_data(client_id);

        // features @1 :List(Text) → ptr[1]
        {
            let mut feat_list = client.reborrow().get_pointer_field(1)
                .init_list(ElementSize::Pointer, features.len() as u32);
            for (i, &feat) in features.iter().enumerate() {
                feat_list.reborrow().get_pointer_element(i as u32)
                    .set_text(feat.into());
            }
        }

        // version @2 :Text → ptr[2]
        client.reborrow().get_pointer_field(2).set_text(version.into());

        // arch @3 :Text → ptr[3]
        client.get_pointer_field(3).set_text(arch.into());
    }

    Ok(())
}
