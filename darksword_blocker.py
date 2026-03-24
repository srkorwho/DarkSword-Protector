import logging
from mitmproxy import http

from urllib.parse import urlparse, parse_qs


logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("DarkSwordProtector")



DARKSWORD_KEYWORDS = [
    b"jsc_base", b"fakeobj", b"addrof", 
    b"gadget_control_1", b"gadget_control_2", b"gadget_control_3", 
    b"gadget_loop_1", b"gadget_loop_2", b"gadget_loop_3", 
    b"gadget_set_all_registers", b"load_x0_0x0_gadget",
    b"rce_offsets", b"sbx1_offsets", b"dyld_signPointer_gadget", 
    b"paciza_invoker", b"slow_fcall_1", b"prepare_dlopen_workers",
    b"tcall_CRLG", b"tcall_X0LG", b"tcall_RLG", b"tcall_CSSG", 
    b"tcall_DSSG", b"tcall_DG", b"jsvm_isNAN_fcall_gadget", 
    b"_4_fcalls", b"fcall_14_args_write_x8", b"sbx1_begin", b"LPE_64BITE",
    b"dyld__dlopen_from_lambda_ret", b"JavaScriptCore__jitAllowList",
    b"gpuDlsym", b"gpuPacia", b"gpuPacib", b"trigger_dlopen1", b"trigger_dlopen2",
    b"rce_worker", b"rce_module", b"dlopen_workers_prepared",
    b"stage1_rce", b"setup_fcall", b"slow_fcall_done", b"sign_pointers",
    b"gadget_control_1_ios184", b"gadget_control_2_ios184", b"gadget_control_3_ios184", 
    b"gadget_loop_1_ios184", b"gadget_loop_2_ios184", b"gadget_loop_3_ios184", 
    b"gadget_set_all_registers_ios184",
    b"mach_vm_allocate", b"mach_vm_deallocate", b"mach_vm_read",
    b"mach_vm_map", b"mach_vm_remap", b"mach_make_memory_entry_64",
    b"mmap", b"munmap", b"msync", b"mprotect",
    b"mach_absolute_time", b"mach_timebase_info", b"bootstrap_look_up",
    b"mach_port_allocate", b"mach_port_mod_refs", b"mach_port_deallocate",
    b"mach_port_destroy", b"mach_port_insert_right", b"mach_msg",
    b"mach_msg_send", b"pthread_self", b"pthread_create_suspended_np",
    b"pthread_attr_init", b"pthread_attr_setstacksize", b"pthread_attr_setstackaddr",
    b"pthread_mach_thread_np", b"pthread_join", b"pthread_yield_np",
    b"thread_suspend", b"thread_resume", b"thread_terminate",
    b"pthread_mutex_lock", b"pthread_mutex_unlock", b"ulock_wait",
    b"pthread_create_auth_stub", b"pthread_linkedit",
    b"sandbox_extension_issue_file", b"sandbox_extension_consume", 
    b"memorystatus_control", b"TASK_EXC_GUARD_MP_CORPSE", 
    b"TASK_EXC_GUARD_MP_FATAL", b"TASK_EXC_GUARD_MP_DELIVER",
    b"MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK", 
    b"MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT", 
    b"MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED",
    b"com.apple.app-sandbox.read-write", b"applySandboxEscape", 
    b"adjustMemoryPressure", b"applyTokensForRemoteTask",
    b"MigFilterBypassThread", b"keychain_copier.js", 
    b"wifi_password_dump.js", b"wifi_password_securityd.js",
    b"icloud_dumper.js", b"file_downloader.js", 
    b"libs_Chain_Native__WEBPACK_IMPORTED_MODULE",
    b"libs_Chain_Chain__WEBPACK_IMPORTED_MODULE",
    b"libs_TaskRop_TaskRop__WEBPACK_IMPORTED_MODULE",
    b"libs_TaskRop_Task__WEBPACK_IMPORTED_MODULE",
    b"libs_TaskRop_Sandbox__WEBPACK_IMPORTED_MODULE",
    b"/private/var/Keychains/keychain-2.db", b"/private/var/Keychains/keychain-2.db-shm",
    b"/private/var/Keychains/keychain-2.db-wal", b"/private/var/Keychains/keychain-2.db-journal",
    b"/private/var/protected/trustd/private/TrustStore.sqlite3", b"/private/var/mobile/Library/SMS/",
    b"/private/var/mobile/Library/CallHistoryDB/", b"/private/var/mobile/Library/AddressBook/",
    b"/private/var/mobile/Library/Voicemail/", b"/private/var/keybags/systembag.kb",
    b"/private/var/keybags/persona.kb", b"/private/var/keybags/usersession.kb",
    b"/private/var/preferences/SystemConfiguration/com.apple.wifi.plist",
    b"/private/var/preferences/com.apple.wifi.known-networks.plist",
    b"/private/var/mobile/Library/CoreDuet/", b"/private/var/mobile/Library/PersonalizationPortrait/",
    b"/private/var/mobile/Library/Health/", b"/private/var/root/Library/Lockdown/",
    b"/private/var/mobile/Library/Accounts/", b"/private/var/mobile/Library/Mail/",  
    b"AVFAudio__AVLoadSpeechSynthesisImplementation_onceToken",
    b"AVFAudio__OBJC_CLASS__AVSpeechSynthesisMarker",
    b"AVFAudio__OBJC_CLASS__AVSpeechSynthesisProviderRequest",
    b"AVFAudio__OBJC_CLASS__AVSpeechSynthesisVoice",
    b"AVFAudio__OBJC_CLASS__AVSpeechUtterance",
    b"AVFAudio__cfstr_SystemLibraryTextToSpeech",
    b"AXCoreUtilities__DefaultLoader",
    b"CAPointer", b"CFNetwork__gConstantCFStringValueTable",
    b"CGContextDelegate", b"CMPhoto__CMPhotoCompressionCreateContainerFromImageExt",
    b"CMPhoto__CMPhotoCompressionCreateDataContainerFromImage",
    b"CMPhoto__CMPhotoCompressionSessionAddAuxiliaryImage",
    b"CMPhoto__CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation",
    b"CMPhoto__CMPhotoCompressionSessionAddCustomMetadata",
    b"CMPhoto__CMPhotoCompressionSessionAddExif",
    b"CMPhoto__kCMPhotoTranscodeOption_Strips",
    b"DesktopServicesPriv_bss", b"Foundation__NSBundleTables_bundleTables_value",
    b"GPUConnectionToWebProcess_m_remoteGraphicsContextGLMap",
    b"GPUProcess_singleton", b"GetCurrentThreadTLSIndex_CurrentThreadIndex",
    b"HOMEUI_cstring", b"IOSurfaceContextDelegate", b"IOSurfaceDrawable",
    b"IOSurfaceQueue", b"ImageIO__IIOLoadCMPhotoSymbols",
    b"ImageIO__gFunc_CMPhotoCompressionCreateContainerFromImageExt",
    b"ImageIO__gFunc_CMPhotoCompressionCreateDataContainerFromImage",
    b"ImageIO__gFunc_CMPhotoCompressionSessionAddAuxiliaryImage",
    b"ImageIO__gFunc_CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation",
    b"ImageIO__gFunc_CMPhotoCompressionSessionAddCustomMetadata",
    b"ImageIO__gFunc_CMPhotoCompressionSessionAddExif",
    b"ImageIO__gImageIOLogProc", b"JavaScriptCore__globalFuncParseFloat",
    b"JavaScriptCore__jitAllowList_once",
    b"MediaAccessibility__MACaptionAppearanceGetDisplayType",
    b"PerfPowerServicesReader_cstring", b"RemoteGraphicsContextGLWorkQueue",
    b"RemoteRenderingBackendProxy_off", b"Security__SecKeychainBackupSyncable_block_invoke",
    b"Security__SecOTRSessionProcessPacketRemote_block_invoke",
    b"Security__gSecurityd",
    b"TextToSpeech__OBJC_CLASS__TtC12TextToSpeech27TTSMagicFirstPartyAudioUnit",
    b"UI_m_connection", b"WebCore__DedicatedWorkerGlobalScope_vtable",
    b"WebCore__PAL_getPKContactClass",
    b"WebCore__TelephoneNumberDetector_phoneNumbersScanner_value",
    b"WebCore__ZZN7WebCoreL29allScriptExecutionContextsMapEvE8contexts",
    b"WebCore__initPKContact_once", b"WebCore__initPKContact_value",
    b"WebCore__softLinkDDDFACacheCreateFromFramework",
    b"WebCore__softLinkDDDFAScannerFirstResultInUnicharArray",
    b"WebCore__softLinkMediaAccessibilityMACaptionAppearanceGetDisplayType",
    b"WebCore__softLinkOTSVGOTSVGTableRelease",
    b"WebProcess_ensureGPUProcessConnection", b"WebProcess_gpuProcessConnectionClosed",
    b"WebProcess_singleton", b"__pthread_head", b"dyld__RuntimeState_emptySlot",
    b"dyld__RuntimeState_vtable", b"dyld__signPointer", b"emptyString",
    b"free_slabs", b"libARI_cstring", b"libGPUCompilerImplLazy__invoker",
    b"libGPUCompilerImplLazy_cstring", b"libdyld__dlopen", b"libdyld__dlsym",
    b"libdyld__gAPIs", b"libsystem_c__atexit_mutex", b"libsystem_kernel__thread_suspend",
    b"libsystem_pthread_base", b"m_backend", b"m_drawingArea", b"m_gpuProcessConnection",
    b"m_gpuProcessConnection_m_identifier", b"m_imageBuffer", b"m_isRenderingSuspended",
    b"m_platformContext", b"m_remoteDisplayLists", b"m_remoteRenderingBackendMap",
    b"m_webProcessConnections", b"mach_task_self_ptr", b"mainRunLoop", b"privateState_off",
    b"pthread_create_jsc", b"pthread_create_offset", b"runLoopHolder_tid",
    b"rxBufferMtl_off", b"rxMtlBuffer_off", b"vertexAttribVector_off",
    b"malloc_restore_0_gadget", b"malloc_restore_1_gadget", b"malloc_restore_2_gadget",
    b"malloc_restore_3_gadget", b"_CFObjectCopyProperty", b"load_x1x3x8",
    b"jsvm_isNAN_fcall_gadget2", b"store_x0_x0", b"mov_x0_x22", b"str_x1_x2",
    b"add_x22_0x90", b"transformSurface_gadget", b"xpac_gadget",
    b"wait_for_jit_compilation_ms", b"shared_cache_slide", b"dyld_patching_fptr_offset",
     b"iPhone11,2_4_6_22F76", b"iPhone11,8_22F76", b"iPhone12,1_22F76",
    b"iPhone12,3_5_22F76", b"iPhone12,8_22F76", b"iPhone13,1_22F76",
    b"iPhone13,2_3_22F76", b"iPhone13,4_22F76", b"iPhone14,2_22F76",
    b"iPhone14,3_22F76", b"iPhone14,4_22F76", b"iPhone14,5_22F76",
    b"iPhone14,6_22F76", b"iPhone14,7_22F76", b"iPhone14,8_22F76",
    b"iPhone15,2_22F76", b"iPhone15,3_22F76", b"iPhone15,4_22F76",
    b"iPhone15,5_22F76", b"iPhone16,1_22F76", b"iPhone16,2_22F76",
     b"iPhone11,2_4_6_22E240", b"iPhone11,8_22E240", b"iPhone12,1_22E240",
    b"iPhone12,3_5_22E240", b"iPhone12,8_22E240", b"iPhone13,1_22E240",
    b"iPhone13,2_3_22E240", b"iPhone13,4_22E240", b"iPhone14,2_22E240",
    b"iPhone14,3_22E240", b"iPhone14,4_22E240", b"iPhone14,5_22E240",
    b"iPhone14,6_22E240", b"iPhone14,7_22E240", b"iPhone14,8_22E240",
    b"iPhone15,2_22E240", b"iPhone15,3_22E240", b"iPhone15,4_22E240",
    b"iPhone15,5_22E240", b"iPhone16,1_22E240", b"iPhone16,2_22E240",
    b"iPhone17,1_22E240", b"iPhone17,2_22E240", b"iPhone17,3_22E240",
    b"iPhone17,4_22E240", b"iPhone17,5_22E240",
    b"iPhone11,2_4_6_22G86", b"iPhone11,8_22G86", b"iPhone12,1_22G86",
    b"iPhone12,3_5_22G86", b"iPhone12,8_22G86", b"iPhone13,1_22G86",
    b"iPhone13,2_3_22G86", b"iPhone13,4_22G86", b"iPhone14,2_22G86",
    b"iPhone14,3_22G86", b"iPhone14,4_22G86", b"iPhone14,5_22G86",
    b"iPhone14,6_22G86", b"iPhone14,7_22G86", b"iPhone14,8_22G86",
    b"iPhone15,2_22G86", b"iPhone15,3_22G86", b"iPhone15,4_22G86",
    b"iPhone15,5_22G86", b"iPhone16,1_22G86", b"iPhone16,2_22G86",
    b"iPhone17,1_22G86", b"iPhone17,2_22G86", b"iPhone17,3_22G86",
    b"iPhone17,4_22G86", b"iPhone17,5_22G86",
b"iPhone11,2_4_6_22G90", b"iPhone11,8_22G90", b"iPhone12,1_22G90",
    b"iPhone12,3_5_22G90", b"iPhone12,8_22G90", b"iPhone13,1_22G90",
    b"iPhone13,2_3_22G90", b"iPhone13,4_22G90", b"iPhone14,2_22G90",
    b"iPhone14,3_22G90", b"iPhone14,4_22G90", b"iPhone14,5_22G90",
    b"iPhone14,6_22G90", b"iPhone14,7_22G90", b"iPhone14,8_22G90",
    b"iPhone15,2_22G90", b"iPhone15,3_22G90", b"iPhone15,4_22G90",
    b"iPhone15,5_22G90", b"iPhone16,1_22G90", b"iPhone16,2_22G90",
    b"iPhone17,1_22G90", b"iPhone17,2_22G90", b"iPhone17,3_22G90",
    b"iPhone17,4_22G90", b"iPhone17,5_22G90",
 b"iPhone11,2_4_6_22G100", b"iPhone11,8_22G100", b"iPhone12,1_22G100",
    b"iPhone12,3_5_22G100", b"iPhone12,8_22G100", b"iPhone13,1_22G100",
    b"iPhone13,2_3_22G100", b"iPhone13,4_22G100", b"iPhone14,2_22G100",
    b"iPhone14,3_22G100", b"iPhone14,4_22G100", b"iPhone14,5_22G100",
    b"iPhone14,6_22G100", b"iPhone14,7_22G100", b"iPhone14,8_22G100",
    b"iPhone15,2_22G100", b"iPhone15,3_22G100", b"iPhone15,4_22G100",
    b"iPhone15,5_22G100", b"iPhone16,1_22G100", b"iPhone16,2_22G100",
    b"iPhone17,1_22G100", b"iPhone17,2_22G100", b"iPhone17,3_22G100",
    b"iPhone17,4_22G100", b"iPhone17,5_22G100",
b"0b92b8b2602c011d1831c6c27ef74b76", b"f35b705e8c57ae59e369ebc9145a9dbc",
    b"43ba9900ff2fc7d9d32072540b2cab12", b"c90776dbac058ed6957f476e287867f8",
    b"22f32fd975a694d340a6ad22b872b1ae", b"c33e4990a9d3afe948b98d7d4205d596",
    b"6149d995753968891870832e3fec9195",
b"/private/var/mobile/Containers/Data/Application/", b"/private/var/mobile/Containers/Shared/AppGroup/",
    b"/private/var/preferences/SystemConfiguration/preferences.plist", b"/private/var/mobile/Library/Safari/",
    b"/private/var/mobile/Library/Cookies/", b"/private/var/mobile/Library/Caches/locationd/",
    b"/private/var/mobile/Library/Notes/", b"/private/var/mobile/Library/Calendar/",
    b"/private/var/mobile/Media/PhotoData/", b"/private/var/mobile/Library/Mobile Documents/",
    b"/private/var/mobile/Library/FrontBoard/",
 b"\\u4444", 
    b"noPAC",
    b"OffscreenCanvas(1, 1)", b"createImageBitmap", b"uread64", b"uwrite64",
    b"pacia", b"pacib", b"data_ptr", b"check_attempt", b"sbx0_main",
    b"sbx1_main", b"xpac", b"BigInt.prototype.add", b"BigInt.prototype.sub",
    b"bluetoothd", b"SpringBoard", b"launchd", b"configd", b"wifid", 
    b"securityd", b"UserEventAgent",b"oxpc_get_type_descriptor", b"OXPC_TYPE_STRING", b"OXPC_TYPE_INT64", 
    b"OXPC_TYPE_UINT64", b"OXPC_TYPE_ARRAY", b"OXPC_TYPE_DICTIONARY", 
    b"OXPC_TYPE_OOL_DATA", b"OXPC_TYPE_UUID", b"OXPC_TYPE_MACH_SEND", 
    b"OXPC_TYPE_DATA", b"OXPC_TYPE_NULL", b"OXPC_TYPE_INVALID",
    b"oxpc_string_type_descriptor", b"oxpc_int64_type_descriptor", 
    b"oxpc_uint64_type_descriptor", b"oxpc_array_type_descriptor", 
    b"oxpc_dictionary_type_descriptor", b"oxpc_ool_data_type_descriptor", 
    b"oxpc_uuid_type_descriptor", b"oxpc_mach_send_type_descriptor", 
    b"oxpc_data_type_descriptor", b"oxpc_null_type_descriptor", 
    b"oxpc_invalid_type_descriptor"
]

class DarkSwordBlocker:
    def __init__(self):
       
        self.allowed_urls = {}

    def request(self, flow: http.HTTPFlow) -> None:
        
        if flow.request.method == "POST" and flow.request.path == "/__darksword_proceed":
            content = flow.request.content.decode('utf-8', errors='ignore')
            params = parse_qs(content)
            target_url = params.get('target_url', [''])[0]
            
            if target_url:
                client_ip = flow.client_conn.peername[0]
                self.allowed_urls[(client_ip, target_url)] = True
                logger.info(f"User {client_ip} explicitly allowed payload to {target_url}")
                
               
                flow.response = http.Response.make(
                    302,
                    b"",
                    {
                        "Location": target_url.encode('utf-8')
                    }
                )

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response or not flow.response.content:
            return

        client_ip = flow.client_conn.peername[0]
        target_url = flow.request.url

       
        if (client_ip, target_url) in self.allowed_urls:
            logger.info(f"Allowing previously intercepted traffic to {target_url} based on user consent.")
            
            return

        content_type = flow.response.headers.get("Content-Type", "").lower()
        if any(skip_type in content_type for skip_type in ["image/", "video/", "audio/", "font/"]):
            return
        flow.response.decode()
        content = flow.response.content
        

        for keyword in DARKSWORD_KEYWORDS:
            if keyword in content:
                self.intercept_request(flow, f"Found DarkSword Indicator: {keyword.decode('utf-8', errors='ignore')}")
                return

    def intercept_request(self, flow: http.HTTPFlow, reason: str):
        target_url = flow.request.url
        logger.warning(f"Intercepted potential DarkSword payload at {target_url}")
        logger.warning(f"Reason: {reason}")
        
        flow.response.status_code = 403
        flow.response.headers["Content-Type"] = "text/html"
        flow.response.content = f"""
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Intercepted: DarkSword Protector</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f8f9fa; color: #333; text-align: center; padding: 40px 20px; }}
                h1 {{ color: #dc3545; }}
                .container {{ background: white; max-width: 600px; margin: 0 auto; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .alert {{ background-color: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; border: 1px solid #f5c6cb; margin-bottom: 20px; font-weight: bold; overflow-wrap: break-word; }}
                .footer {{ margin-top: 30px; color: #6c757d; font-size: 0.85em; }}
                .btn {{ display: inline-block; padding: 10px 20px; color: white; background-color: #dc3545; text-decoration: none; border-radius: 5px; border: none; font-size: 16px; cursor: pointer; margin-top: 20px; }}
                .btn-proceed {{ background-color: #6c757d; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Security Intercept</h1>
                <div class="alert">
                    Malicious Content Intercepted (DarkSword RCE Signature Detected)
                </div>
                <p>This page or its resources were stopped because they contain code patterns heavily associated with the <b>DarkSword iOS RCE exploit</b>.</p>
                <div style="font-size: 0.8em; color: #666; background: #eee; padding: 10px; border-radius: 5px; margin-top: 15px;">
                    <b>Detection Reason:</b><br/> {reason}
                </div>
                
                <p style="margin-top: 20px; color: #666; font-size: 0.9em;">
                    We strongly recommend against proceeding. This page may attempt to compromise your iOS device and steal your data.
                </p>

                <form method="POST" action="/__darksword_proceed">
                    <input type="hidden" name="target_url" value="{target_url}">
                    <button type="submit" class="btn btn-proceed">Proceed Anyway (I Understand the Risks)</button>
                </form>
                
                <div class="footer">
                    Protected by <b>DarkSword-Protector</b> Mitmproxy Addon
                </div>
            </div>
        </body>
        </html>
        """.encode("utf-8")

addons = [
    DarkSwordBlocker()
]
