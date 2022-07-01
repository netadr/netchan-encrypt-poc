#pragma once

namespace Game
{
	template <typename T> static void DB_ConvertOffsetToPointer(T* pointer)
	{
		Utils::Hook::Call<void(T*)>(0x4A82B0)(pointer);
	}
	template <typename T> static T** DB_InsertPointer()
	{
		static auto DB_InsertPointer_Address = 0x43B290;
		T** retval = nullptr;
		
		__asm
		{
			call DB_InsertPointer_Address;
			mov retval, eax;
		}

		return retval;
	}

	std::vector<std::string> Sys_ListFilesWrapper(const std::string& directory, const std::string& extension);
	
	typedef void(__cdecl * AddRefToObject_t)(unsigned int id);
	extern AddRefToObject_t AddRefToObject;

	typedef unsigned int(__cdecl * AllocObject_t)();
	extern AllocObject_t AllocObject;

	typedef void(__cdecl * AddRefToValue_t)(int type, VariableUnion u);
	extern AddRefToValue_t AddRefToValue;

	typedef unsigned int(__cdecl * AllocThread_t)(unsigned int self);
	extern AllocThread_t AllocThread;

	typedef unsigned int(__cdecl * VM_Execute_0_t)(unsigned int localId, const char* pos, unsigned int paramcount);
	extern VM_Execute_0_t VM_Execute_0;

	typedef void(__cdecl * AngleVectors_t)(float *angles, float *forward, float *right, float *up);
	extern AngleVectors_t AngleVectors;

	typedef unsigned int(__cdecl * BG_GetNumWeapons_t)();
	extern BG_GetNumWeapons_t BG_GetNumWeapons;

	typedef const char*(__cdecl * BG_GetWeaponName_t)(unsigned int index);
	extern BG_GetWeaponName_t BG_GetWeaponName;

	typedef void*(__cdecl * BG_LoadWeaponDef_LoadObj_t)(const char* filename);
	extern BG_LoadWeaponDef_LoadObj_t BG_LoadWeaponDef_LoadObj;

	typedef WeaponDef*(__cdecl * BG_GetWeaponDef_t)(unsigned int weaponIndex);
	extern BG_GetWeaponDef_t BG_GetWeaponDef;

	typedef const char*(__cdecl * BG_GetEntityTypeName_t)(const int eType);
	extern BG_GetEntityTypeName_t BG_GetEntityTypeName;

	typedef void(__cdecl * Cbuf_AddServerText_t)();
	extern Cbuf_AddServerText_t Cbuf_AddServerText;

	typedef void(__cdecl * Cbuf_AddText_t)(int localClientNum, const char* text);
	extern Cbuf_AddText_t Cbuf_AddText;

	typedef void(__cdecl * Cbuf_InsertText_t)(int localClientNum, const char* text);
	extern Cbuf_InsertText_t Cbuf_InsertText;

	typedef int(__cdecl * CG_GetClientNum_t)();
	extern CG_GetClientNum_t CG_GetClientNum;

	typedef void(__cdecl * CG_NextWeapon_f_t)();
	extern CG_NextWeapon_f_t CG_NextWeapon_f;

	typedef std::int32_t(__cdecl * CG_PlayBoltedEffect_t) (std::int32_t, FxEffectDef*, std::int32_t, std::uint32_t);
	extern CG_PlayBoltedEffect_t CG_PlayBoltedEffect;

	typedef std::int32_t(__cdecl * CG_GetBoneIndex_t)(std::int32_t, std::uint32_t name, char* index);
	extern CG_GetBoneIndex_t CG_GetBoneIndex;

	typedef void(__cdecl * CG_ScoresDown_f_t)();
	extern CG_ScoresDown_f_t CG_ScoresDown_f;

	typedef void(__cdecl * CG_ScoresUp_f_t)();
	extern CG_ScoresUp_f_t CG_ScoresUp_f;

	typedef void(__cdecl * CG_ScrollScoreboardUp_t)(cg_s* cgameGlob);
	extern CG_ScrollScoreboardUp_t CG_ScrollScoreboardUp;

	typedef void(__cdecl * CG_ScrollScoreboardDown_t)(cg_s* cgameGlob);
	extern CG_ScrollScoreboardDown_t CG_ScrollScoreboardDown;

	typedef const char*(__cdecl * CG_GetTeamName_t)(team_t team);
	extern CG_GetTeamName_t CG_GetTeamName;

	typedef void(__cdecl * CG_SetupWeaponDef_t)(int localClientNum, unsigned int weapIndex);
	extern CG_SetupWeaponDef_t CG_SetupWeaponDef;

	typedef char*(__cdecl * CL_GetClientName_t)(int localClientNum, int index, char *buf, size_t size);
	extern CL_GetClientName_t CL_GetClientName;

	typedef int(__cdecl * CL_IsCgameInitialized_t)();
	extern CL_IsCgameInitialized_t CL_IsCgameInitialized;

	typedef void(__cdecl * CL_ConnectFromParty_t)(int controllerIndex, _XSESSION_INFO *hostInfo, netadr_t addr, int numPublicSlots, int numPrivateSlots, const char *mapname, const char *gametype);
	extern CL_ConnectFromParty_t CL_ConnectFromParty;

	typedef void(__cdecl * CL_DownloadsComplete_t)(int controller);
	extern CL_DownloadsComplete_t CL_DownloadsComplete;

	typedef void(_cdecl * CL_DrawStretchPicPhysical_t)(float x, float y, float w, float h, float xScale, float yScale, float xay, float yay, const float *color, Game::Material* material);
	extern CL_DrawStretchPicPhysical_t CL_DrawStretchPicPhysical;

	typedef const char*(_cdecl* CL_GetConfigString_t)(int index);
	extern CL_GetConfigString_t CL_GetConfigString;

	typedef int(_cdecl* CL_GetMaxRank_t)();
	extern CL_GetMaxRank_t CL_GetMaxRank;

	typedef int(_cdecl* CL_GetRankForXP_t)(int xp);
	extern CL_GetRankForXP_t CL_GetRankForXP;

	typedef void(__cdecl * CL_GetRankIcon_t)(int level, int prestige, Material** material);
	extern CL_GetRankIcon_t CL_GetRankIcon;

	typedef void(__cdecl * CL_HandleRelayPacket_t)(Game::msg_t* msg, int client);
	extern CL_HandleRelayPacket_t CL_HandleRelayPacket;

	typedef void(__cdecl * CL_ResetViewport_t)();
	extern CL_ResetViewport_t CL_ResetViewport;

	typedef void(__cdecl * CL_SelectStringTableEntryInDvar_f_t)();
	extern CL_SelectStringTableEntryInDvar_f_t CL_SelectStringTableEntryInDvar_f;

	typedef void(__cdecl * CL_DrawStretchPic_t)(const ScreenPlacement* scrPlace, float x, float y, float w, float h, int horzAlign, int vertAlign, float s1, float t1, float s2, float t2, const float* color, Material* material);
	extern CL_DrawStretchPic_t CL_DrawStretchPic;

	typedef void(__cdecl * CL_ConsoleFixPosition_t)();
	extern CL_ConsoleFixPosition_t CL_ConsoleFixPosition;

	typedef void(__cdecl * Cmd_AddCommand_t)(const char* cmdName, void(*function), cmd_function_t* allocedCmd, bool isKey);
	extern Cmd_AddCommand_t Cmd_AddCommand;

	typedef void(__cdecl * Cmd_AddServerCommand_t)(const char* name, void(*callback), cmd_function_t* data);
	extern Cmd_AddServerCommand_t Cmd_AddServerCommand;

	typedef void(__cdecl * Cmd_ExecuteSingleCommand_t)(int localClientNum, int controllerIndex, const char* cmd);
	extern Cmd_ExecuteSingleCommand_t Cmd_ExecuteSingleCommand;

	typedef void(__cdecl * Com_ClientPacketEvent_t)();
	extern Com_ClientPacketEvent_t Com_ClientPacketEvent;

	typedef void(__cdecl * Com_Error_t)(errorParm_t type, const char* message, ...);
	extern Com_Error_t Com_Error;

	typedef void(__cdecl * Com_Printf_t)(int channel, const char* fmt, ...);
	extern Com_Printf_t Com_Printf;

	typedef void(__cdecl * Com_PrintError_t)(int channel, const char* fmt, ...);
	extern Com_PrintError_t Com_PrintError;

	typedef void(__cdecl * Com_PrintWarning_t)(int channel, const char* fmt, ...);
	extern Com_PrintWarning_t  Com_PrintWarning;

	typedef void(__cdecl * Com_PrintMessage_t)(int channel, const char* msg, int error);
	extern Com_PrintMessage_t Com_PrintMessage;

	typedef void(__cdecl * Com_EndParseSession_t)();
	extern Com_EndParseSession_t Com_EndParseSession;

	typedef void(__cdecl * Com_BeginParseSession_t)(const char* filename);
	extern Com_BeginParseSession_t Com_BeginParseSession;

	typedef void(__cdecl * Com_SetSpaceDelimited_t)(int);
	extern Com_SetSpaceDelimited_t Com_SetSpaceDelimited;

	typedef char*(__cdecl * Com_Parse_t)(const char** data_p);
	extern Com_Parse_t Com_Parse;

	typedef bool (__cdecl * Com_MatchToken_t)(const char **data_p, const char* token, int size);
	extern Com_MatchToken_t Com_MatchToken;

	typedef void(__cdecl * Com_SetSlowMotion_t)(float start, float end, int duration);
	extern Com_SetSlowMotion_t Com_SetSlowMotion;

	typedef void(__cdecl * Com_Quitf_t)();
	extern Com_Quitf_t Com_Quit_f;

	typedef char* (__cdecl * Con_DrawMiniConsole_t)(int localClientNum, int xPos, int yPos, float alpha);
	extern Con_DrawMiniConsole_t Con_DrawMiniConsole;

	typedef void (__cdecl * Con_DrawSolidConsole_t)();
	extern Con_DrawSolidConsole_t Con_DrawSolidConsole;

	typedef bool(__cdecl * Con_CancelAutoComplete_t)();
	extern Con_CancelAutoComplete_t Con_CancelAutoComplete;

	typedef char *(__cdecl *DB_AllocStreamPos_t)(int alignment);
	extern DB_AllocStreamPos_t DB_AllocStreamPos;

	typedef void(__cdecl * DB_PushStreamPos_t)(unsigned int index);
	extern DB_PushStreamPos_t DB_PushStreamPos;

	typedef void(__cdecl * DB_PopStreamPos_t)();
	extern DB_PopStreamPos_t DB_PopStreamPos;

	typedef void(__cdecl * DB_BeginRecoverLostDevice_t)();
	extern DB_BeginRecoverLostDevice_t DB_BeginRecoverLostDevice;

	typedef void(__cdecl * DB_EndRecoverLostDevice_t)();
	extern DB_EndRecoverLostDevice_t DB_EndRecoverLostDevice;

	typedef void(__cdecl * DB_EnumXAssets_t)(XAssetType type, void(*)(XAssetHeader, void *), void* userdata, bool overrides);
	extern DB_EnumXAssets_t DB_EnumXAssets;

	typedef void(__cdecl * DB_EnumXAssets_Internal_t)(XAssetType type, void(*)(XAssetHeader, void *), void* userdata, bool overrides);
	extern DB_EnumXAssets_Internal_t DB_EnumXAssets_Internal;

	typedef XAssetHeader (__cdecl * DB_FindXAssetHeader_t)(XAssetType type, const char* name);
	extern DB_FindXAssetHeader_t DB_FindXAssetHeader;

	typedef float(__cdecl * DB_GetLoadedFraction_t)();
	extern DB_GetLoadedFraction_t DB_GetLoadedFraction;

	typedef const char* (__cdecl * DB_GetXAssetNameHandler_t)(XAssetHeader* asset);
	extern DB_GetXAssetNameHandler_t* DB_GetXAssetNameHandlers;

	typedef int(__cdecl * DB_GetXAssetSizeHandler_t)();
	extern DB_GetXAssetSizeHandler_t* DB_GetXAssetSizeHandlers;

	typedef const char *(__cdecl * DB_GetXAssetTypeName_t)(XAssetType type);
	extern DB_GetXAssetTypeName_t DB_GetXAssetTypeName;

	typedef const char *(__cdecl * DB_IsXAssetDefault_t)(XAssetType type, const char* name);
	extern DB_IsXAssetDefault_t DB_IsXAssetDefault;

	typedef void(__cdecl * DB_GetRawBuffer_t)(RawFile* rawfile, char* buffer, int size);
	extern DB_GetRawBuffer_t DB_GetRawBuffer;

	typedef int(__cdecl * DB_GetRawFileLen_t)(RawFile* rawfile);
	extern DB_GetRawFileLen_t DB_GetRawFileLen;

	typedef void(*DB_LoadXAssets_t)(XZoneInfo *zoneInfo, unsigned int zoneCount, int sync);
	extern DB_LoadXAssets_t DB_LoadXAssets;

	typedef void(*DB_LoadXFileData_t)(char *pos, int size);
	extern DB_LoadXFileData_t DB_LoadXFileData;

	typedef void(__cdecl * DB_ReadXFileUncompressed_t)(void* buffer, int size);
	extern DB_ReadXFileUncompressed_t DB_ReadXFileUncompressed;

	typedef void(__cdecl * DB_ReadXFile_t)(void* buffer, int size);
	extern DB_ReadXFile_t DB_ReadXFile;

	typedef void(__cdecl * DB_ReleaseXAssetHandler_t)(XAssetHeader header);
	extern DB_ReleaseXAssetHandler_t* DB_ReleaseXAssetHandlers;

	typedef void(__cdecl * DB_SetXAssetName_t)(XAsset* asset, const char* name);
	extern DB_SetXAssetName_t DB_SetXAssetName;

	typedef void(__cdecl * DB_SetXAssetNameHandler_t)(XAssetHeader* header, const char* name);
	extern DB_SetXAssetNameHandler_t* DB_SetXAssetNameHandlers;

	typedef void(__cdecl * DB_XModelSurfsFixup_t)(XModel* model);
	extern DB_XModelSurfsFixup_t DB_XModelSurfsFixup;

	typedef dvar_t*(__cdecl * Dvar_RegisterBool_t)(const char* dvarName, bool value, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterBool_t Dvar_RegisterBool;

	typedef dvar_t*(__cdecl * Dvar_RegisterFloat_t)(const char* dvarName, float value, float min, float max, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterFloat_t Dvar_RegisterFloat;

	typedef dvar_t*(__cdecl * Dvar_RegisterVec2_t)(const char* dvarName, float x, float y, float min, float max, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterVec2_t Dvar_RegisterVec2;

	typedef dvar_t*(__cdecl * Dvar_RegisterVec3_t)(const char* dvarName, float x, float y, float z, float min, float max, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterVec3_t Dvar_RegisterVec3;

	typedef dvar_t*(__cdecl * Dvar_RegisterVec4_t)(const char* dvarName, float x, float y, float z, float w, float min, float max, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterVec4_t Dvar_RegisterVec4;

	typedef dvar_t*(__cdecl * Dvar_RegisterInt_t)(const char* dvarName, int value, int min, int max, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterInt_t Dvar_RegisterInt;

	typedef dvar_t*(__cdecl * Dvar_RegisterEnum_t)(const char* dvarName, const char** valueList, int defaultIndex, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterEnum_t Dvar_RegisterEnum;

	typedef dvar_t*(__cdecl * Dvar_RegisterString_t)(const char* dvarName, const char* value, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterString_t Dvar_RegisterString;

	typedef dvar_t*(__cdecl * Dvar_RegisterColor_t)(const char* dvarName, float r, float g, float b, float a, unsigned __int16 flags, const char* description);
	extern Dvar_RegisterColor_t Dvar_RegisterColor;

	typedef void(__cdecl * Dvar_SetFromStringByName_t)(const char* dvarName, const char* string);
	extern Dvar_SetFromStringByName_t Dvar_SetFromStringByName;

	typedef const dvar_t*(__cdecl * Dvar_SetFromStringByNameFromSource_t)(const char* dvarName, const char* string, DvarSetSource source);
	extern Dvar_SetFromStringByNameFromSource_t Dvar_SetFromStringByNameFromSource;

	typedef void(__cdecl * Dvar_SetStringByName_t)(const char* dvarName, const char* value);
	extern Dvar_SetStringByName_t Dvar_SetStringByName;

	typedef void(__cdecl * Dvar_SetString_t)(const dvar_t* dvar, const char* value);
	extern Dvar_SetString_t Dvar_SetString;

	typedef void(__cdecl * Dvar_SetBool_t)(const dvar_t* dvar, bool enabled);
	extern Dvar_SetBool_t Dvar_SetBool;

	typedef void(__cdecl * Dvar_SetFloat_t)(const dvar_t* dvar, float value);
	extern Dvar_SetFloat_t Dvar_SetFloat;

	typedef void(__cdecl * Dvar_SetInt_t)(const dvar_t* dvar, int integer);
	extern Dvar_SetInt_t Dvar_SetInt;

	typedef void(__cdecl * Dvar_GetUnpackedColorByName_t)(const char* dvarName, float* expandedColor);
	extern Dvar_GetUnpackedColorByName_t Dvar_GetUnpackedColorByName;

	typedef dvar_t*(__cdecl * Dvar_FindVar_t)(const char* dvarName);
	extern Dvar_FindVar_t Dvar_FindVar;

	typedef char*(__cdecl * Dvar_InfoString_Big_t)(int bit);
	extern Dvar_InfoString_Big_t Dvar_InfoString_Big;

	typedef void(__cdecl * Dvar_SetCommand_t)(const char* dvarName, const char* string);
	extern Dvar_SetCommand_t Dvar_SetCommand;

	typedef const char*(__cdecl * Dvar_DisplayableValue_t)(const dvar_t* dvar);
	extern Dvar_DisplayableValue_t Dvar_DisplayableValue;

	typedef bool(__cdecl * Encode_Init_t)(const char* );
	extern Encode_Init_t Encode_Init;

	typedef void(__cdecl * Field_Clear_t)(void* field);
	extern Field_Clear_t Field_Clear;

	typedef void(__cdecl * FreeMemory_t)(void* buffer);
	extern FreeMemory_t FreeMemory;

	typedef void (__cdecl * Free_String_t)(const char* string);
	extern Free_String_t Free_String;

	typedef void(__cdecl * FS_FreeFile_t)(void* buffer);
	extern FS_FreeFile_t FS_FreeFile;

	typedef int(__cdecl * FS_ReadFile_t)(const char* path, char** buffer);
	extern FS_ReadFile_t FS_ReadFile;

	typedef char** (__cdecl * FS_GetFileList_t)(const char *path, const char *extension, FsListBehavior_e behavior, int *numfiles, int allocTrackType);
	extern FS_GetFileList_t FS_GetFileList;

	typedef void(__cdecl * FS_FreeFileList_t)(char** list);
	extern FS_FreeFileList_t FS_FreeFileList;

	typedef int(__cdecl * FS_FOpenFileAppend_t)(const char* file);
	extern FS_FOpenFileAppend_t FS_FOpenFileAppend;
	extern FS_FOpenFileAppend_t FS_FOpenFileWrite;

	typedef int(__cdecl * FS_FOpenFileRead_t)(const char* file, int* fh/*, int uniqueFile*/);
	extern FS_FOpenFileRead_t FS_FOpenFileRead;

	typedef int(__cdecl * FS_FOpenFileReadForThread_t)(const char *filename, int *file, int thread);
	extern FS_FOpenFileReadForThread_t FS_FOpenFileReadForThread;

	typedef int(__cdecl * FS_FCloseFile_t)(int stream);
	extern FS_FCloseFile_t FS_FCloseFile;

	typedef bool(__cdecl * FS_FileExists_t)(const char* file);
	extern FS_FileExists_t FS_FileExists;

	typedef bool(__cdecl * FS_WriteFile_t)(char* filename, char* folder, void* buffer, int size);
	extern FS_WriteFile_t FS_WriteFile;

	typedef int(__cdecl * FS_Write_t)(const void* buffer, size_t size, int file);
	extern FS_Write_t FS_Write;

	typedef int(__cdecl * FS_Printf_t)(int file, const char* fmt, ...);
	extern FS_Printf_t FS_Printf;

	typedef int(__cdecl * FS_Read_t)(void* buffer, size_t size, int file);
	extern FS_Read_t FS_Read;

	typedef int(__cdecl * FS_Seek_t)(int fileHandle, int seekPosition, int seekOrigin);
	extern FS_Seek_t FS_Seek;

	typedef int(__cdecl * FS_FTell_t)(int fileHandle);
	extern FS_FTell_t FS_FTell;

	typedef int(__cdecl * FS_Remove_t)(char *);
	extern FS_Remove_t FS_Remove;

	typedef int(__cdecl * FS_Restart_t)(int localClientNum, int checksumFeed);
	extern FS_Restart_t FS_Restart;

	typedef int(__cdecl * FS_BuildPathToFile_t)(const char*, const char*, const char*, char**);
	extern FS_BuildPathToFile_t FS_BuildPathToFile;

	typedef iwd_t*(__cdecl * FS_IsShippedIWD_t)(const char* fullpath, const char* iwd);
	extern FS_IsShippedIWD_t FS_IsShippedIWD;

	typedef int(__cdecl* FS_Delete_t)(const char* fileName);
	extern FS_Delete_t FS_Delete;

	typedef void(__cdecl * G_LogPrintf_t)(const char* fmt, ...);
	extern G_LogPrintf_t G_LogPrintf;

	typedef unsigned int(__cdecl * G_GetWeaponIndexForName_t)(const char*);
	extern G_GetWeaponIndexForName_t G_GetWeaponIndexForName;

	typedef void(__cdecl * G_SpawnEntitiesFromString_t)();
	extern G_SpawnEntitiesFromString_t G_SpawnEntitiesFromString;

	typedef gentity_s*(__cdecl * G_Spawn_t)();
	extern G_Spawn_t G_Spawn;

	typedef void(__cdecl * G_FreeEntity_t)(gentity_s* ed);
	extern G_FreeEntity_t G_FreeEntity;

	typedef void(__cdecl * G_SpawnItem_t)(gentity_s* ent, int item);
	extern G_SpawnItem_t G_SpawnItem;

	typedef void(__cdecl * G_GetItemClassname_t)(int item, gentity_s* ent);
	extern G_GetItemClassname_t G_GetItemClassname;

	typedef void(__cdecl * G_PrintEntities_t)();
	extern G_PrintEntities_t G_PrintEntities;

	typedef const char*(__cdecl * G_GetEntityTypeName_t)(const gentity_s* ent);
	extern G_GetEntityTypeName_t G_GetEntityTypeName;

	typedef void(__cdecl * Svcmd_EntityList_f_t)();
	extern Svcmd_EntityList_f_t Svcmd_EntityList_f;

	typedef void(__cdecl * GScr_LoadGameTypeScript_t)();
	extern GScr_LoadGameTypeScript_t GScr_LoadGameTypeScript;

	typedef int(__cdecl * Reader_t)(char const*, int *);
	typedef bool(__cdecl * Image_LoadFromFileWithReader_t)(GfxImage* image, Reader_t reader);
	extern Image_LoadFromFileWithReader_t Image_LoadFromFileWithReader;

	typedef void(__cdecl * Image_Release_t)(GfxImage* image);
	extern Image_Release_t Image_Release;

	typedef char*(__cdecl * Info_ValueForKey_t)(const char* infoString, const char* key);
	extern Info_ValueForKey_t Info_ValueForKey;

	typedef void(__cdecl * Key_SetCatcher_t)(int localClientNum, int catcher);
	extern Key_SetCatcher_t Key_SetCatcher;

	typedef void(__cdecl * Key_RemoveCatcher_t)(int localClientNum, int andMask);
	extern Key_RemoveCatcher_t Key_RemoveCatcher;

	typedef bool(__cdecl * Key_IsKeyCatcherActive_t)(int localClientNum, int catcher);
	extern Key_IsKeyCatcherActive_t Key_IsKeyCatcherActive;

	typedef void(__cdecl * Key_SetBinding_t)(int localClientNum, int keyNum, const char* binding);
	extern Key_SetBinding_t Key_SetBinding;

	typedef void(__cdecl * LargeLocalInit_t)();
	extern LargeLocalInit_t LargeLocalInit;

	typedef bool(__cdecl * Load_Stream_t)(bool atStreamStart, const void* ptr, unsigned int size);
	extern Load_Stream_t Load_Stream;

	typedef void(__cdecl * Load_XString_t)(bool atStreamStart);
	extern Load_XString_t Load_XString;

	typedef void(__cdecl * Load_XModelPtr_t)(bool atStreamStart);
	extern Load_XModelPtr_t Load_XModelPtr;

	typedef void(__cdecl * Load_XModelSurfsFixup_t)(XModelSurfs**, XModelLodInfo*);
	extern Load_XModelSurfsFixup_t Load_XModelSurfsFixup;

	typedef void(__cdecl * Load_XStringArray_t)(bool atStreamStart, int count);
	extern Load_XStringArray_t Load_XStringArray;

	typedef void(__cdecl * Load_XStringCustom_t)(const char** str);
	extern Load_XStringCustom_t Load_XStringCustom;

	typedef void(__cdecl * Load_FxEffectDefHandle_t)(bool atStreamStart);
	extern Load_FxEffectDefHandle_t Load_FxEffectDefHandle;

	typedef void(__cdecl * Load_FxElemDef_t)(bool atStreamStart);
	extern Load_FxElemDef_t Load_FxElemDef;

	typedef void(__cdecl * Load_GfxImagePtr_t)(bool atStreamStart);
	extern Load_GfxImagePtr_t Load_GfxImagePtr;

	typedef void(__cdecl * Load_GfxTextureLoad_t)(bool atStreamStart);
	extern Load_GfxTextureLoad_t Load_GfxTextureLoad;

	typedef int(__cdecl * Load_Texture_t)(GfxImageLoadDef** loadDef, GfxImage* image);
	extern Load_Texture_t Load_Texture;

	typedef void(__cdecl * Load_SndAliasCustom_t)(snd_alias_list_t** var);
	extern Load_SndAliasCustom_t Load_SndAliasCustom;

	typedef void(__cdecl * Load_MaterialHandle_t)(bool atStreamStart);
	extern Load_MaterialHandle_t Load_MaterialHandle;

	typedef void(__cdecl * Load_PhysCollmapPtr_t)(bool atStreamStart);
	extern Load_PhysCollmapPtr_t Load_PhysCollmapPtr;

	typedef void(__cdecl * Load_PhysPresetPtr_t)(bool atStreamStart);
	extern Load_PhysPresetPtr_t Load_PhysPresetPtr;

	typedef void(__cdecl * Load_TracerDefPtr_t)(bool atStreamStart);
	extern Load_TracerDefPtr_t Load_TracerDefPtr;

	typedef void(__cdecl * Load_snd_alias_list_nameArray_t)(bool atStreamStart, int count);
	extern Load_snd_alias_list_nameArray_t Load_snd_alias_list_nameArray;

	typedef void(__cdecl * Menus_CloseAll_t)(UiContext* dc);
	extern Menus_CloseAll_t Menus_CloseAll;

	typedef void(__cdecl * Menus_CloseRequest_t)(UiContext* dc, menuDef_t* menu);
	extern Menus_CloseRequest_t Menus_CloseRequest;

	typedef int(__cdecl * Menus_OpenByName_t)(UiContext* dc, const char* p);
	extern Menus_OpenByName_t Menus_OpenByName;

	typedef menuDef_t *(__cdecl * Menus_FindByName_t)(UiContext* dc, const char* name);
	extern Menus_FindByName_t Menus_FindByName;

	typedef bool(__cdecl * Menu_IsVisible_t)(UiContext* dc, menuDef_t* menu);
	extern Menu_IsVisible_t Menu_IsVisible;

	typedef bool(__cdecl * Menus_MenuIsInStack_t)(UiContext* dc, menuDef_t* menu);
	extern Menus_MenuIsInStack_t Menus_MenuIsInStack;

	typedef menuDef_t*(__cdecl * Menu_GetFocused_t)(UiContext* ctx);
	extern Menu_GetFocused_t Menu_GetFocused;

	typedef void(__cdecl * Menu_HandleKey_t)(UiContext* ctx, menuDef_t* menu, Game::keyNum_t key, int down);
	extern Menu_HandleKey_t Menu_HandleKey;

	typedef bool(__cdecl * UI_KeyEvent_t)(int clientNum, int key, int down);
	extern UI_KeyEvent_t UI_KeyEvent;
	
	typedef const char*(__cdecl * UI_SafeTranslateString_t)(const char* reference);
	extern UI_SafeTranslateString_t UI_SafeTranslateString;
	
	typedef void(__cdecl * UI_ReplaceConversions_t)(const char* sourceString, ConversionArguments* arguments, char* outputString, size_t outputStringSize);
	extern UI_ReplaceConversions_t UI_ReplaceConversions;
	
	typedef void(__cdecl * MSG_Init_t)(msg_t* buf, char* data, int length);
	extern MSG_Init_t MSG_Init;

	typedef void(__cdecl * MSG_ReadData_t)(msg_t* msg, void* data, int len);
	extern MSG_ReadData_t MSG_ReadData;

	typedef int(__cdecl * MSG_ReadLong_t)(msg_t* msg);
	extern MSG_ReadLong_t MSG_ReadLong;

	typedef int(__cdecl * MSG_ReadBit_t)(msg_t* msg);
	extern MSG_ReadBit_t MSG_ReadBit;

	typedef int(__cdecl * MSG_ReadBits_t)(msg_t* msg, int bits);
	extern MSG_ReadBits_t MSG_ReadBits;

	typedef short(__cdecl * MSG_ReadShort_t)(msg_t* msg);
	extern MSG_ReadShort_t MSG_ReadShort;

	typedef __int64(__cdecl * MSG_ReadInt64_t)(msg_t* msg);
	extern MSG_ReadInt64_t MSG_ReadInt64;

	typedef char* (__cdecl * MSG_ReadString_t)(msg_t* msg);
	extern MSG_ReadString_t MSG_ReadString;

	typedef char* (__cdecl * MSG_ReadStringLine_t)(msg_t *msg, char *string, unsigned int maxChars);
	extern MSG_ReadStringLine_t MSG_ReadStringLine;

	typedef int(__cdecl * MSG_ReadByte_t)(msg_t* msg);
	extern MSG_ReadByte_t MSG_ReadByte;

	typedef int(__cdecl * MSG_ReadBitsCompress_t)(const char *from, char *to, int size);
	extern MSG_ReadBitsCompress_t MSG_ReadBitsCompress;

	typedef void(__cdecl * MSG_WriteByte_t)(msg_t* msg, unsigned char c);
	extern MSG_WriteByte_t MSG_WriteByte;

	typedef void(__cdecl * MSG_WriteData_t)(msg_t *buf, const void *data, int length);
	extern MSG_WriteData_t MSG_WriteData;

	typedef void(__cdecl * MSG_WriteLong_t)(msg_t *msg, int c);
	extern MSG_WriteLong_t MSG_WriteLong;

	typedef void(__cdecl * MSG_WriteShort_t)(msg_t* msg, short s);
	extern MSG_WriteShort_t MSG_WriteShort;

	typedef void(__cdecl * MSG_WriteString_t)(msg_t* msg, const char *str);
	extern MSG_WriteString_t MSG_WriteString;

	typedef int(__cdecl * MSG_WriteBitsCompress_t)(bool trainHuffman, const char *from, char *to, int size);
	extern MSG_WriteBitsCompress_t MSG_WriteBitsCompress;

	typedef void(__cdecl * NetadrToSockadr_t)(netadr_t *a, sockaddr *s);
	extern NetadrToSockadr_t NetadrToSockadr;

	typedef const char* (__cdecl * NET_AdrToString_t)(netadr_t adr);
	extern NET_AdrToString_t NET_AdrToString;

	typedef bool(__cdecl * NET_CompareAdr_t)(netadr_t a, netadr_t b);
	extern NET_CompareAdr_t NET_CompareAdr;

	typedef void(__cdecl * NET_DeferPacketToClient_t)(netadr_t *, msg_t *);
	extern NET_DeferPacketToClient_t NET_DeferPacketToClient;

	typedef const char* (__cdecl * NET_ErrorString_t)();
	extern NET_ErrorString_t NET_ErrorString;

	typedef void(__cdecl * NET_Init_t)();
	extern NET_Init_t NET_Init;

	typedef bool(__cdecl * NET_IsLocalAddress_t)(netadr_t adr);
	extern NET_IsLocalAddress_t NET_IsLocalAddress;

	typedef int(__cdecl * NET_StringToAdr_t)(const char *s, netadr_t *a);
	extern NET_StringToAdr_t NET_StringToAdr;

	typedef void(__cdecl * NET_OutOfBandPrint_t)(netsrc_t sock, netadr_t adr, const char *data);
	extern NET_OutOfBandPrint_t NET_OutOfBandPrint;

	typedef void(__cdecl * NET_OutOfBandData_t)(netsrc_t sock, netadr_t adr, const char *format, int len);
	extern NET_OutOfBandData_t NET_OutOfBandData;

	typedef void(__cdecl * Live_MPAcceptInvite_t)(_XSESSION_INFO *hostInfo, const int controllerIndex, bool fromGameInvite);
	extern Live_MPAcceptInvite_t Live_MPAcceptInvite;

	typedef int(__cdecl * Live_GetMapIndex_t)(const char* mapname);
	extern Live_GetMapIndex_t Live_GetMapIndex;

	typedef int(__cdecl * Live_GetPrestige_t)(int controllerIndex);
	extern Live_GetPrestige_t Live_GetPrestige;

	typedef int(__cdecl * Live_GetXp_t)(int controllerIndex);
	extern Live_GetXp_t Live_GetXp;

	typedef char* (__cdecl * LoadModdableRawfile_t)(int a1, const char* filename);
	extern LoadModdableRawfile_t LoadModdableRawfile;

	typedef int(__cdecl * PC_ReadToken_t)(source_t*, token_t*);
	extern PC_ReadToken_t PC_ReadToken;

	typedef int(__cdecl * PC_ReadTokenHandle_t)(int handle, pc_token_s *pc_token);
	extern PC_ReadTokenHandle_t PC_ReadTokenHandle;

	typedef void(__cdecl * PC_SourceError_t)(int, const char*, ...);
	extern PC_SourceError_t PC_SourceError;

	typedef int(__cdecl * Party_GetMaxPlayers_t)(party_s* party);
	extern Party_GetMaxPlayers_t Party_GetMaxPlayers;

	typedef int(__cdecl * PartyHost_CountMembers_t)(PartyData_s* party);
	extern PartyHost_CountMembers_t PartyHost_CountMembers;

	typedef netadr_t *(__cdecl * PartyHost_GetMemberAddressBySlot_t)(int unk, void *party, const int slot);
	extern PartyHost_GetMemberAddressBySlot_t PartyHost_GetMemberAddressBySlot;

	typedef const char *(__cdecl * PartyHost_GetMemberName_t)(PartyData_s* party, const int clientNum);
	extern PartyHost_GetMemberName_t PartyHost_GetMemberName;

	typedef void(__cdecl * Playlist_ParsePlaylists_t)(const char* data);
	extern Playlist_ParsePlaylists_t Playlist_ParsePlaylists;

	typedef Font_s*(__cdecl * R_RegisterFont_t)(const char* asset, int safe);
	extern R_RegisterFont_t R_RegisterFont;

	typedef void(__cdecl * R_AddCmdDrawText_t)(const char *text, int maxChars, Font_s *font, float x, float y, float xScale, float yScale, float rotation, const float *color, int style);
	extern R_AddCmdDrawText_t R_AddCmdDrawText;

	typedef void(_cdecl * R_AddCmdDrawStretchPic_t)(float x, float y, float w, float h, float xScale, float yScale, float xay, float yay, const float *color, Game::Material* material);
	extern R_AddCmdDrawStretchPic_t R_AddCmdDrawStretchPic;

	typedef void* (__cdecl * R_AllocStaticIndexBuffer_t)(IDirect3DIndexBuffer9** store, int length);
	extern R_AllocStaticIndexBuffer_t R_AllocStaticIndexBuffer;

	typedef bool(__cdecl * R_Cinematic_StartPlayback_Now_t)();
	extern R_Cinematic_StartPlayback_Now_t R_Cinematic_StartPlayback_Now;

	typedef void(__cdecl * R_LoadGraphicsAssets_t)();
	extern R_LoadGraphicsAssets_t R_LoadGraphicsAssets;

	typedef int(__cdecl * R_TextWidth_t)(const char* text, int maxlength, Font_s* font);
	extern R_TextWidth_t R_TextWidth;

	typedef int(__cdecl * R_TextHeight_t)(Font_s* font);
	extern R_TextHeight_t R_TextHeight;

	typedef void(__cdecl * R_FlushSun_t)();
	extern R_FlushSun_t R_FlushSun;

	typedef GfxWorld*(__cdecl * R_SortWorldSurfaces_t)();
	extern R_SortWorldSurfaces_t R_SortWorldSurfaces;

	typedef void(__cdecl * RemoveRefToObject_t)(unsigned int id);
	extern RemoveRefToObject_t RemoveRefToObject;

	typedef void(__cdecl * Scr_AddEntity_t)(const gentity_s* ent);
	extern Scr_AddEntity_t Scr_AddEntity;

	typedef void(__cdecl * Scr_AddString_t)(const char* value);
	extern Scr_AddString_t Scr_AddString;

	typedef void(__cdecl * Scr_AddConstString_t)(unsigned int value);
	extern Scr_AddConstString_t Scr_AddConstString;

	typedef void(__cdecl * Scr_AddIString_t)(const char* value);
	extern Scr_AddIString_t Scr_AddIString;

	typedef void(__cdecl * Scr_AddInt_t)(int value);
	extern Scr_AddInt_t Scr_AddInt;

	typedef void(__cdecl * Scr_AddFloat_t)(float value);
	extern Scr_AddFloat_t Scr_AddFloat;

	typedef void(__cdecl * Scr_AddObject_t)(unsigned int id);
	extern Scr_AddObject_t Scr_AddObject;

	typedef void(__cdecl * Scr_ShutdownAllocNode_t)();
	extern Scr_ShutdownAllocNode_t Scr_ShutdownAllocNode;

	typedef int(__cdecl * Scr_LoadGameType_t)();
	extern Scr_LoadGameType_t Scr_LoadGameType;

	typedef int(__cdecl * Scr_LoadScript_t)(const char*);
	extern Scr_LoadScript_t Scr_LoadScript;

	typedef const char*(__cdecl * Scr_GetString_t)(unsigned int index);
	extern Scr_GetString_t Scr_GetString;

	typedef scr_string_t(__cdecl * Scr_GetConstString_t)(unsigned int index);
	extern Scr_GetConstString_t Scr_GetConstString;

	typedef const char*(__cdecl * Scr_GetDebugString_t)(unsigned int index);
	extern Scr_GetDebugString_t Scr_GetDebugString;

	typedef float(__cdecl * Scr_GetFloat_t)(unsigned int index);
	extern Scr_GetFloat_t Scr_GetFloat;

	typedef int(__cdecl * Scr_GetInt_t)(unsigned int index);
	extern Scr_GetInt_t Scr_GetInt;

	typedef unsigned int(__cdecl * Scr_GetObject_t)(unsigned int index);
	extern Scr_GetObject_t Scr_GetObject;

	typedef unsigned int(__cdecl * Scr_GetNumParam_t)();
	extern Scr_GetNumParam_t Scr_GetNumParam;

	typedef unsigned int(__cdecl * Scr_GetEntityId_t)(int entnum, unsigned int classnum);
	extern Scr_GetEntityId_t Scr_GetEntityId;

	typedef int(__cdecl * Scr_GetFunctionHandle_t)(const char* filename, const char* name);
	extern Scr_GetFunctionHandle_t Scr_GetFunctionHandle;

	typedef int(__cdecl * Scr_ExecThread_t)(int, int);
	extern Scr_ExecThread_t Scr_ExecThread;

	typedef int(__cdecl * Scr_ExecEntThread_t)(gentity_s* ent, int handle, unsigned int paramcount);
	extern Scr_ExecEntThread_t Scr_ExecEntThread;

	typedef int(__cdecl * Scr_FreeThread_t)(int);
	extern Scr_FreeThread_t Scr_FreeThread;

	typedef void(__cdecl * Scr_Notify_t)(gentity_t *ent, unsigned __int16 stringValue, unsigned int paramcount);
	extern Scr_Notify_t Scr_Notify;

	typedef void(__cdecl * Scr_NotifyLevel_t)(unsigned __int16 stringValue, unsigned int paramcount);
	extern Scr_NotifyLevel_t Scr_NotifyLevel;

	typedef void(__cdecl * Scr_ClearOutParams_t)();
	extern Scr_ClearOutParams_t Scr_ClearOutParams;

	typedef void(__cdecl * Scr_RegisterFunction_t)(int func, const char* name);
	extern Scr_RegisterFunction_t Scr_RegisterFunction;

	typedef bool(__cdecl * Scr_IsSystemActive_t)();
	extern Scr_IsSystemActive_t Scr_IsSystemActive;

	typedef int(__cdecl * Scr_GetType_t)(unsigned int index);
	extern Scr_GetType_t Scr_GetType;

	typedef int(__cdecl * Scr_GetPointerType_t)(unsigned int index);
	extern Scr_GetPointerType_t Scr_GetPointerType;

	typedef void(__cdecl * Scr_Error_t)(const char*);
	extern Scr_Error_t Scr_Error;

	typedef void(__cdecl * Scr_ObjectError_t)(const char*);
	extern Scr_ObjectError_t Scr_ObjectError;

	typedef void(__cdecl * Scr_ParamError_t)(unsigned int paramIndex, const char*);
	extern Scr_ParamError_t Scr_ParamError;

	typedef void(__cdecl * Scr_GetObjectField_t)(unsigned int classnum, int entnum, int offset);
	extern Scr_GetObjectField_t Scr_GetObjectField;

	typedef int(__cdecl * Scr_SetObjectField_t)(unsigned int classnum, int entnum, int offset);
	extern Scr_SetObjectField_t Scr_SetObjectField;

	typedef void(__cdecl * Scr_SetClientField_t)(gclient_s* client, int offset);
	extern Scr_SetClientField_t Scr_SetClientField;

	typedef void(__cdecl * Scr_GetEntityField_t)(int entnum, int offset);
	extern Scr_GetEntityField_t Scr_GetEntityField;

	typedef void(__cdecl * Scr_AddClassField_t)(unsigned int classnum, const char* name, unsigned int offset);
	extern Scr_AddClassField_t Scr_AddClassField;

	typedef gentity_s*(__cdecl * GetPlayerEntity_t)(scr_entref_t entref);
	extern GetPlayerEntity_t GetPlayerEntity;

	typedef gentity_s*(__cdecl * GetEntity_t)(scr_entref_t entref);
	extern GetEntity_t GetEntity;

	typedef script_t* (__cdecl * Script_Alloc_t)(int length);
	extern Script_Alloc_t Script_Alloc;

	typedef void(__cdecl * Script_SetupTokens_t)(script_t* script, void* tokens);
	extern Script_SetupTokens_t Script_SetupTokens;

	typedef int(__cdecl * Script_CleanString_t)(char* buffer);
	extern Script_CleanString_t Script_CleanString;

	typedef char*(__cdecl * SE_Load_t)(const char* file, int Unk);
	extern SE_Load_t SE_Load;

	typedef char*(__cdecl * SEH_StringEd_GetString_t)(const char* string);
	extern SEH_StringEd_GetString_t SEH_StringEd_GetString;

	typedef unsigned int(__cdecl * SEH_ReadCharFromString_t)(const char** text, int* isTrailingPunctuation);
	extern SEH_ReadCharFromString_t SEH_ReadCharFromString;

	typedef int (__cdecl * SEH_GetCurrentLanguage_t)();
	extern SEH_GetCurrentLanguage_t SEH_GetCurrentLanguage;

	typedef const char*(__cdecl * SL_ConvertToString_t)(scr_string_t stringValue);
	extern SL_ConvertToString_t SL_ConvertToString;

	typedef short(__cdecl * SL_GetString_t)(const char *str, unsigned int user);
	extern SL_GetString_t SL_GetString;

	typedef void(__cdecl * SL_AddRefToString_t)(unsigned int stringValue);
	extern SL_AddRefToString_t SL_AddRefToString;

	typedef void(__cdecl * SL_RemoveRefToString_t)(unsigned int stringValue);
	extern SL_RemoveRefToString_t SL_RemoveRefToString;

	typedef void(__cdecl * SND_Init_t)(int a1, int a2, int a3);
	extern SND_Init_t SND_Init;

	typedef void(__cdecl * SND_InitDriver_t)();
	extern SND_InitDriver_t SND_InitDriver;

	typedef void(__cdecl * SockadrToNetadr_t)(sockaddr *s, netadr_t *a);
	extern SockadrToNetadr_t SockadrToNetadr;

	typedef void(__cdecl * Steam_JoinLobby_t)(SteamID, char);
	extern Steam_JoinLobby_t Steam_JoinLobby;

	typedef const char*(__cdecl * StringTable_Lookup_t)(const StringTable *table, const int comparisonColumn, const char *value, const int valueColumn);
	extern StringTable_Lookup_t StringTable_Lookup;

	typedef const char* (__cdecl * StringTable_GetColumnValueForRow_t)(const StringTable* table, int, int column);
	extern StringTable_GetColumnValueForRow_t StringTable_GetColumnValueForRow;

	typedef int(__cdecl * StringTable_HashString_t)(const char* string);
	extern StringTable_HashString_t StringTable_HashString;

	typedef gentity_t*(__cdecl* SV_AddTestClient_t)();
	extern SV_AddTestClient_t SV_AddTestClient;

	typedef int(__cdecl * SV_IsTestClient_t)(int clientNum);
	extern SV_IsTestClient_t SV_IsTestClient;

	typedef int(__cdecl* SV_GameClientNum_Score_t)(int clientID);
	extern SV_GameClientNum_Score_t SV_GameClientNum_Score;

	typedef void(__cdecl * SV_GameSendServerCommand_t)(int clientNum, svscmd_type type, const char* text);
	extern SV_GameSendServerCommand_t SV_GameSendServerCommand;

	typedef void(__cdecl * SV_Cmd_TokenizeString_t)(const char* string);
	extern SV_Cmd_TokenizeString_t SV_Cmd_TokenizeString;

	typedef void(__cdecl * SV_Cmd_EndTokenizedString_t)();
	extern SV_Cmd_EndTokenizedString_t SV_Cmd_EndTokenizedString;

	typedef void(__cdecl * SV_Cmd_ArgvBuffer_t)(int arg, char* buf, int size);
	extern SV_Cmd_ArgvBuffer_t SV_Cmd_ArgvBuffer;

	typedef void(__cdecl * SV_SetConfigstring_t)(int index, const char* string);
	extern SV_SetConfigstring_t SV_SetConfigstring;

	typedef void(__cdecl * SV_DirectConnect_t)(netadr_t adr);
	extern SV_DirectConnect_t SV_DirectConnect;

	typedef bool(__cdecl * SV_Loaded_t)();
	extern SV_Loaded_t SV_Loaded;

	typedef void(__cdecl * SV_ClientThink_t)(client_s*, usercmd_s*);
	extern SV_ClientThink_t SV_ClientThink;

	typedef void(__cdecl * SV_DropClient_t)(client_t* drop, const char* reason, bool tellThem);
	extern SV_DropClient_t SV_DropClient;

	typedef client_t*(__cdecl * SV_GetPlayerByName_t)();
	extern SV_GetPlayerByName_t SV_GetPlayerByName;

	typedef client_t*(__cdecl * SV_GetPlayerByNum_t)();
	extern SV_GetPlayerByNum_t SV_GetPlayerByNum;

	typedef void(__cdecl * Sys_Error_t)(const char* error, ...);
	extern Sys_Error_t Sys_Error;

	typedef void(__cdecl * Sys_FreeFileList_t)(char** list);
	extern Sys_FreeFileList_t Sys_FreeFileList;

	typedef int(__cdecl * Sys_IsDatabaseReady_t)();
	extern Sys_IsDatabaseReady_t Sys_IsDatabaseReady;

	typedef int(__cdecl * Sys_IsDatabaseReady2_t)();
	extern Sys_IsDatabaseReady2_t Sys_IsDatabaseReady2;

	typedef bool(__cdecl * Sys_IsMainThread_t)();
	extern Sys_IsMainThread_t Sys_IsMainThread;

	typedef bool(__cdecl * Sys_IsRenderThread_t)();
	extern Sys_IsRenderThread_t Sys_IsRenderThread;

	typedef bool(__cdecl * Sys_IsServerThread_t)();
	extern Sys_IsServerThread_t Sys_IsServerThread;

	typedef bool(__cdecl * Sys_IsDatabaseThread_t)();
	extern Sys_IsDatabaseThread_t Sys_IsDatabaseThread;

	typedef char**(__cdecl * Sys_ListFiles_t)(const char* directory, const char* extension, const char* filter, int* numfiles, int wantsubs);
	extern Sys_ListFiles_t Sys_ListFiles;

	typedef int(__cdecl * Sys_Milliseconds_t)();
	extern Sys_Milliseconds_t Sys_Milliseconds;

	typedef void(__cdecl * Sys_LockWrite_t)(FastCriticalSection* critSect);
	extern Sys_LockWrite_t Sys_LockWrite;

	typedef void(__cdecl * Sys_TempPriorityAtLeastNormalBegin_t)(TempPriority*);
	extern Sys_TempPriorityAtLeastNormalBegin_t Sys_TempPriorityAtLeastNormalBegin;

	typedef void(__cdecl * Sys_TempPriorityEnd_t)(TempPriority*);
	extern Sys_TempPriorityEnd_t Sys_TempPriorityEnd;

	typedef void(__cdecl * TeleportPlayer_t)(gentity_t* entity, float* pos, float* orientation);
	extern TeleportPlayer_t TeleportPlayer;

	typedef bool(__cdecl * Sys_SendPacket_t)(netsrc_t sock, size_t len, const char *format, netadr_t adr);
	extern Sys_SendPacket_t Sys_SendPacket;

	typedef void(__cdecl * Sys_ShowConsole_t)();
	extern Sys_ShowConsole_t Sys_ShowConsole;

	typedef void(__cdecl * Sys_SuspendOtherThreads_t)();
	extern Sys_SuspendOtherThreads_t Sys_SuspendOtherThreads;

	typedef void(__cdecl * UI_AddMenuList_t)(UiContext* dc, MenuList* menuList, int close);
	extern UI_AddMenuList_t UI_AddMenuList;
	
	typedef uiMenuCommand_t(__cdecl * UI_GetActiveMenu_t)(int localClientNum);
	extern UI_GetActiveMenu_t UI_GetActiveMenu;

	typedef char*(__cdecl * UI_CheckStringTranslation_t)(char*, char*);
	extern UI_CheckStringTranslation_t UI_CheckStringTranslation;

	typedef MenuList*(__cdecl * UI_LoadMenus_t)(const char* menuFile, int imageTrack);
	extern UI_LoadMenus_t UI_LoadMenus;

	typedef void(__cdecl * UI_UpdateArenas_t)();
	extern UI_UpdateArenas_t UI_UpdateArenas;

	typedef void(__cdecl * UI_SortArenas_t)();
	extern UI_SortArenas_t UI_SortArenas;

	typedef void(__cdecl * UI_DrawHandlePic_t)(ScreenPlacement* scrPlace, float x, float y, float w, float h, int horzAlign, int vertAlign, const float* color, Material* material);
	extern UI_DrawHandlePic_t UI_DrawHandlePic;

	typedef ScreenPlacement*(__cdecl * ScrPlace_GetActivePlacement_t)(int localClientNum);
	extern ScrPlace_GetActivePlacement_t ScrPlace_GetActivePlacement;

	typedef int(__cdecl * UI_TextWidth_t)(const char* text, int maxChars, Font_s* font, float scale);
	extern UI_TextWidth_t UI_TextWidth;

	typedef int(__cdecl * UI_TextHeight_t)(Font_s* font, float scale);
	extern UI_TextHeight_t UI_TextHeight;

	typedef void(__cdecl * UI_DrawText_t)(const ScreenPlacement* scrPlace, const char* text, int maxChars, Font_s* font, float x, float y, int horzAlign, int vertAlign, float scale, const float* color, int style);
	extern UI_DrawText_t UI_DrawText;
	
	typedef Font_s* (__cdecl* UI_GetFontHandle_t)(ScreenPlacement* scrPlace, int fontEnum, float scale);
	extern UI_GetFontHandle_t UI_GetFontHandle;
	
	typedef void(__cdecl* ScrPlace_ApplyRect_t)(const ScreenPlacement* scrPlace, float* x, float* y, float* w, float* h, int horzAlign, int vertAlign);
	extern ScrPlace_ApplyRect_t ScrPlace_ApplyRect;

	typedef const char*(__cdecl * Win_GetLanguage_t)();
	extern Win_GetLanguage_t Win_GetLanguage;

	typedef void(__cdecl * Vec3UnpackUnitVec_t)(PackedUnitVec, vec3_t*);
	extern Vec3UnpackUnitVec_t Vec3UnpackUnitVec;
	
	typedef float(__cdecl * vectoyaw_t)(vec2_t* vec);
	extern vectoyaw_t vectoyaw;
	
	typedef float(__cdecl * AngleNormalize360_t)(float val);
	extern AngleNormalize360_t AngleNormalize360;

	typedef void(__cdecl * unzClose_t)(void* handle);
	extern unzClose_t unzClose;
	
	typedef void(__cdecl* RB_DrawCursor_t)(Material* material, char cursor, float x, float y, float sinAngle, float cosAngle, Font_s* font, float xScale, float yScale, unsigned int color);
	extern RB_DrawCursor_t RB_DrawCursor;
	
	typedef float(__cdecl* R_NormalizedTextScale_t)(Font_s* font, float scale);
	extern R_NormalizedTextScale_t R_NormalizedTextScale;
	
	typedef void(__cdecl * Material_Process2DTextureCoordsForAtlasing_t)(const Material* material, float* s0, float* s1, float* t0, float* t1);
	extern Material_Process2DTextureCoordsForAtlasing_t Material_Process2DTextureCoordsForAtlasing;

	typedef void(__cdecl* Byte4PackRgba_t)(const float* from, char* to);
	extern Byte4PackRgba_t Byte4PackRgba;

	typedef int(__cdecl* RandWithSeed_t)(int* seed);
	extern RandWithSeed_t RandWithSeed;
	
	typedef void(__cdecl* GetDecayingLetterInfo_t)(unsigned int letter, int* randSeed, int decayTimeElapsed, int fxBirthTime, int fxDecayDuration, unsigned __int8 alpha, bool* resultSkipDrawing, char* resultAlpha, unsigned int* resultLetter, bool* resultDrawExtraFxChar);
	extern GetDecayingLetterInfo_t GetDecayingLetterInfo;
	
	typedef void(__cdecl * Field_Draw_t)(int localClientNum, field_t* edit, int x, int y, int horzAlign, int vertAlign);
	extern Field_Draw_t Field_Draw;
	
	typedef void(__cdecl * Field_AdjustScroll_t)(ScreenPlacement* scrPlace, field_t* edit);
	extern Field_AdjustScroll_t Field_AdjustScroll;

	typedef void(__cdecl * AimAssist_ApplyAutoMelee_t)(const AimInput* input, AimOutput* output);
	extern AimAssist_ApplyAutoMelee_t AimAssist_ApplyAutoMelee;

	typedef gentity_s*(__cdecl * Weapon_RocketLauncher_Fire_t)(gentity_s* ent, unsigned int weaponIndex, float spread, weaponParms* wp, const float* gunVel, lockonFireParms* lockParms, bool a7);
	extern Weapon_RocketLauncher_Fire_t Weapon_RocketLauncher_Fire;

	typedef void(__cdecl * Jump_ClearState_t)(playerState_s* ps);
	extern Jump_ClearState_t Jump_ClearState;

	typedef void(__cdecl * PM_playerTrace_t)(pmove_s* pm, trace_t* results, const float* start, const float* end, const Bounds* bounds, int passEntityNum, int contentMask);
	extern PM_playerTrace_t PM_playerTrace;

	typedef void(__cdecl * PM_Trace_t)(pmove_s* pm, trace_t* results, const float* start, const float* end, const Bounds* bounds, int passEntityNum, int contentMask);
	extern PM_Trace_t PM_Trace;

	typedef EffectiveStance(__cdecl * PM_GetEffectiveStance_t)(const playerState_s* ps);
	extern PM_GetEffectiveStance_t PM_GetEffectiveStance;

	typedef int(__cdecl * CL_MouseEvent_t)(int x, int y, int dx, int dy);
	extern CL_MouseEvent_t CL_MouseEvent;

	typedef void(__cdecl * IN_RecenterMouse_t)();
	extern IN_RecenterMouse_t IN_RecenterMouse;

	typedef void(__cdecl * IN_MouseMove_t)();
	extern IN_MouseMove_t IN_MouseMove;

	typedef void(__cdecl * IN_Init_t)();
	extern IN_Init_t IN_Init;

	typedef void(__cdecl * IN_Shutdown_t)();
	extern IN_Shutdown_t IN_Shutdown;

	typedef void(__cdecl * Touch_Item_t)(gentity_s* ent, gentity_s* other, int touched);
	extern Touch_Item_t Touch_Item;

	typedef void(__cdecl * Add_Ammo_t)(gentity_s* ent, unsigned int weaponIndex, unsigned char weaponModel, int count, int fillClip);
	extern Add_Ammo_t Add_Ammo;

	typedef void(__cdecl * ClientUserinfoChanged_t)(int clientNum);
	extern ClientUserinfoChanged_t ClientUserinfoChanged;

	typedef void(__cdecl * player_die_t)(gentity_s* self, const gentity_s* inflictor, gentity_s* attacker, int damage, int meansOfDeath, int iWeapon, const float* vDir, const hitLocation_t hitLoc, int psTimeOffset);
	extern player_die_t player_die;

	typedef bool(__cdecl* IsServerRunning_t)();
	extern IsServerRunning_t IsServerRunning;

	typedef bool(__cdecl* Netchan_Process_t)(netchan_t* chan, msg_t* msg);
	extern Netchan_Process_t Netchan_Process;

	typedef void(__cdecl* SV_FreeClient_t)(client_t* cl);
	extern SV_FreeClient_t SV_FreeClient;

	typedef void(__cdecl* CL_ClearClientState_t)(int localClientNum);
	extern CL_ClearClientState_t CL_ClearClientState;

	typedef void(__cdecl* SV_Live_RemoveClient_t)(client_t* cl, const char* reason, bool tellThem);
	extern SV_Live_RemoveClient_t SV_Live_RemoveClient;

	extern XAssetHeader* DB_XAssetPool;
	extern unsigned int* g_poolSize;

	constexpr auto CMD_MAX_NESTING = 8;
	extern CmdArgs* cmd_args;
	extern CmdArgs* sv_cmd_args;

	extern cmd_function_t** cmd_functions;

	extern float* cl_angles;
	extern float* cgameFOVSensitivityScale;

	extern int* svs_time;
	extern int* svs_clientCount;
	extern client_t* svs_clients;

	extern source_t **sourceFiles;
	extern keywordHash_t **menuParseKeywordHash;

	extern UiContext* uiContext;

	extern int* arenaCount;
	extern mapArena_t* arenas;

	extern int* gameTypeCount;
	extern gameTypeName_t* gameTypes;

	extern searchpath_t** fs_searchpaths;

	extern XBlock** g_streamBlocks;
	extern int* g_streamPos;
	extern int* g_streamPosIndex;

	extern bool* g_lobbyCreateInProgress;
	extern party_t** partyIngame;
	extern PartyData_s** partyData;

	extern int* numIP;
	extern netIP_t* localIP;

	extern int* demoFile;
	extern int* demoPlaying;
	extern int* demoRecording;
	extern int* serverMessageSequence;

	constexpr auto MAX_GENTITIES = 2048u;
	constexpr auto ENTITYNUM_NONE = MAX_GENTITIES - 1;
	extern gentity_t* g_entities;

	extern netadr_t* connectedHost;
	extern SOCKET* ip_socket;

	extern uint32_t* com_frameTime;

	extern SafeArea* safeArea;

	extern SpawnVar* spawnVars;
	extern MapEnts** marMapEntsPtr;

	extern IDirect3D9** d3d9;
	extern IDirect3DDevice9** dx_ptr;

	extern mapname_t* mapnames;

	extern char*** varXString;
	extern TracerDef*** varTracerDefPtr;
	extern XModel*** varXModelPtr;
	extern XModel** varXModel;
	extern PathData** varPathData;
	extern const char** varConstChar;
	extern Material*** varMaterialHandle;
	extern FxEffectDef*** varFxEffectDefHandle;
	extern PhysCollmap*** varPhysCollmapPtr;
	extern PhysPreset*** varPhysPresetPtr;
	extern Game::MaterialPass** varMaterialPass;
	extern snd_alias_list_t*** varsnd_alias_list_name;

	extern FxElemField* s_elemFields;

	extern infoParm_t* infoParams;

	extern XZone* g_zones;
	extern unsigned short* db_hashTable;

	extern scrVmPub_t* scrVmPub;
	extern scrVarPub_t* scrVarPub;

	extern clientstate_t* clcState;

	extern GfxScene* scene;

	extern ConDrawInputGlob* conDrawInputGlob;
	extern field_t* g_consoleField;

	extern clientStatic_t* cls;

	extern sharedUiInfo_t* sharedUiInfo;
	extern ScreenPlacement* scrPlaceFull;
	extern ScreenPlacement* scrPlaceView;
	
	extern clientActive_t* clients;

	extern cg_s* cgArray;
	extern cgs_t* cgsArray;

	extern PlayerKeyState* playerKeys;
	extern kbutton_t* playersKb;
	extern AimAssistGlobals* aaGlobArray;

	constexpr auto KEY_NAME_COUNT = 95;
	constexpr auto LOCALIZED_KEY_NAME_COUNT = 95;
	extern keyname_t* keyNames;
	extern keyname_t* localizedKeyNames;

	constexpr auto AIM_ASSIST_GRAPH_COUNT = 4u;
	extern GraphFloat* aaInputGraph;

	extern const char* MY_CMDS;

	constexpr auto MAX_MODELS = 512;
	extern XModel** cached_models;

	extern float (*CorrectSolidDeltas)[26][3];

	extern FastCriticalSection* db_hashCritSect;

	extern ScreenPlacement* scrPlaceFullUnsafe;

	extern level_locals_t* level;

	extern float (*penetrationDepthTable)[PENETRATE_TYPE_COUNT][SURF_TYPE_COUNT];

	extern WinMouseVars_t* s_wmv;

	extern int* window_center_x;
	extern int* window_center_y;

	extern DeferredQueue* deferredQueue;

	extern int* g_waitingForKey;

	extern Material** whiteMaterial;

	extern unsigned long* _tls_index;

	extern int* cls_uiStarted;

	extern int* com_fixedConsolePosition;

	extern int* com_errorPrintsCount;

	void Sys_LockRead(FastCriticalSection* critSect);
	void Sys_UnlockRead(FastCriticalSection* critSect);

	XModel* G_GetModel(int index);

	ScreenPlacement* ScrPlace_GetUnsafeFullPlacement();

	void UI_FilterStringForButtonAnimation(char* str, unsigned int strMaxSize);

	XAssetHeader ReallocateAssetPool(XAssetType type, unsigned int newSize);
	void Menu_FreeItemMemory(Game::itemDef_s* item);
	void Menu_SetNextCursorItem(Game::UiContext* ctx, Game::menuDef_t* currentMenu, int unk = 1);
	void Menu_SetPrevCursorItem(Game::UiContext* ctx, Game::menuDef_t* currentMenu, int unk = 1);
	const char* TableLookup(StringTable* stringtable, int row, int column);
	const char* UI_LocalizeMapName(const char* mapName);
	const char* UI_LocalizeGameType(const char* gameType);
	float UI_GetScoreboardLeft(void*);

	const char *DB_GetXAssetName(XAsset *asset);
	XAssetType DB_GetXAssetNameType(const char* name);
	int DB_GetZoneIndex(const std::string& name);
	bool DB_IsZoneLoaded(const char* zone);
	void DB_EnumXAssetEntries(XAssetType type, std::function<void(XAssetEntry*)> callback, bool overrides);
	XAssetHeader DB_FindXAssetDefaultHeaderInternal(XAssetType type);
	XAssetEntry* DB_FindXAssetEntry(XAssetType type, const char* name);

	void FS_AddLocalizedGameDirectory(const char *path, const char *dir);

	bool PM_IsAdsAllowed(playerState_s* ps);

	void ShowMessageBox(const std::string& message, const std::string& title);

	unsigned int R_HashString(const char* string);
	unsigned int R_HashString(const char* string, size_t maxLen);
	void R_LoadSunThroughDvars(const char* mapname, sunflare_t* sun);
	void R_SetSunFromDvars(sunflare_t* sun);

	void SV_GameDropClient(int clientNum, const char* reason);
	void SV_DropAllBots();
	void SV_BotUserMove(client_t* client);

	void RuntimeErrorInternal(int channel, const char* codePos, unsigned int index, const char* msg);
	void IncInParam();

	void Scr_NotifyId(unsigned int id, unsigned __int16 stringValue, unsigned int paramcount);
	void Scr_AddBool(int value);

	void IN_KeyUp(kbutton_t* button);
	void IN_KeyDown(kbutton_t* button);

	int FS_FOpenFileReadCurrentThread(const char* file, int* fh);

	void Load_IndexBuffer(void* data, IDirect3DIndexBuffer9** storeHere, int count);
	void Load_VertexBuffer(void* data, IDirect3DVertexBuffer9** where, int len);

	char* Com_GetParseThreadInfo();
	void Com_SetParseNegativeNumbers(int parse);

	int CL_GetMaxXP();

	void Image_Setup(GfxImage* image, unsigned int width, unsigned int height, unsigned int depth, unsigned int flags, _D3DFORMAT format);

	float Vec2Normalize(vec2_t& vec);
	float Vec3Normalize(vec3_t& vec);
	void Vec2UnpackTexCoords(const PackedTexCoords in, vec2_t* out);
	void MatrixVecMultiply(const float(&mulMat)[3][3], const vec3_t& mulVec, vec3_t& solution);
	void QuatRot(vec3_t* vec, const vec4_t* quat);
	void QuatMultiply(const vec4_t* q1, const vec4_t* q2, vec4_t* res);

	void SortWorldSurfaces(GfxWorld* world);
	void R_AddDebugLine(float* color, float* v1, float* v2);
	void R_AddDebugString(float *color, float *pos, float scale, const char *str);
	void R_AddDebugBounds(float* color, Bounds* b);
	void R_AddDebugBounds(float* color, Bounds* b, const float(*quat)[4]);

	Glyph* R_GetCharacterGlyph(Font_s* font, unsigned int letter);
	bool SetupPulseFXVars(const char* text, int maxLength, int fxBirthTime, int fxLetterTime, int fxDecayStartTime, int fxDecayDuration, bool* resultDrawRandChar, int* resultRandSeed, int* resultMaxLength, bool* resultDecaying, int* resultDecayTimeElapsed);
	void RB_DrawChar(Material* material, float x, float y, float w, float h, float sinAngle, float cosAngle, Glyph* glyph, unsigned int color);
	void RB_DrawStretchPicRotate(Material* material, float x, float y, float w, float h, float s0, float t0, float s1, float t1, float sinAngle, float cosAngle, unsigned int color);
	char ModulateByteColors(char colorA, char colorB);

	float GraphGetValueFromFraction(int knotCount, const float(*knots)[2], float fraction);
	float GraphFloat_GetValue(const GraphFloat* graph, const float fraction);

	void AimAssist_UpdateTweakables(int localClientNum);
	void AimAssist_UpdateAdsLerp(const AimInput* input);

	void Dvar_SetVariant(dvar_t* var, DvarValue value, DvarSetSource source);
}
