///////////////////////////////
/// Authorization key creation
///////////////////////////////

resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ;

p_q_inner_data#83c95aec pq:bytes p:bytes q:bytes nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data;

server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params;
server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:bytes = Server_DH_Params;

server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:bytes g_a:bytes server_time:int = Server_DH_inner_data;

client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:bytes = Client_DH_Inner_Data;

dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;
dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer;
dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer;

destroy_auth_key_ok#f660e1d4 = DestroyAuthKeyRes;
destroy_auth_key_none#0a9f2259 = DestroyAuthKeyRes;
destroy_auth_key_fail#ea109b13 = DestroyAuthKeyRes;

---functions---

req_pq#60469778 nonce:int128 = ResPQ;

req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:bytes q:bytes public_key_fingerprint:long encrypted_data:bytes = Server_DH_Params;

set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128 encrypted_data:bytes = Set_client_DH_params_answer;

destroy_auth_key#d1435160 = DestroyAuthKeyRes;

/// Other

---types---

msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;

rpc_error#2144ca19 error_code:int error_message:string = RpcError;

future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt;
future_salts#ae500895 req_msg_id:long now:int salts:vector<FutureSalt> = FutureSalts;

//message msg_id:long seqno:int body:WithSize<Object> = manual.Message; // parsed manually
//msg_container#73f1f8dc messages:vector<message> = manual.MessageContainer; // parsed manually

// Just add a constructor so that P_Q_inner_data was an enum like in non-minimized schema
p_q_inner_data_temp#3c6a84d4 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 expires_in:int = P_Q_inner_data;

---functions---

initConnection#c7481da6 {X:Type} api_id:int device_model:string system_version:string app_version:string system_lang_code:string lang_pack:string lang_code:string query:!X = X;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;

---types---

dcOption#5d8c6cc flags:# ipv6:flags.0?true media_only:flags.1?true tcpo_only:flags.2?true cdn:flags.3?true static:flags.4?true id:int ip_address:string port:int = DcOption;

config#7feec888 flags:# phonecalls_enabled:flags.1?true date:int expires:int test_mode:Bool this_dc:int dc_options:Vector<DcOption> chat_size_max:int megagroup_size_max:int forwarded_count_max:int online_update_period_ms:int offline_blur_timeout_ms:int offline_idle_timeout_ms:int online_cloud_timeout_ms:int notify_cloud_delay_ms:int notify_default_delay_ms:int chat_big_size:int push_chat_period_ms:int push_chat_limit:int saved_gifs_limit:int edit_time_limit:int rating_e_decay:int stickers_recent_limit:int tmp_sessions:flags.0?int pinned_dialogs_count_max:int call_receive_timeout_ms:int call_ring_timeout_ms:int call_connect_timeout_ms:int call_packet_timeout_ms:int me_url_prefix:string suggested_lang_code:flags.2?string lang_pack_version:flags.2?int disabled_features:Vector<DisabledFeature> = Config;

disabledFeature#ae636f24 feature:string description:string = DisabledFeature;

---functions---

help.getConfig#c4f9186b = Config;
