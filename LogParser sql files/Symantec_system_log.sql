SELECT FileName,
	CASE Field2
		WHEN 'CVE'
			THEN ''
		WHEN NULL
			THEN ''
		ELSE TO_STRING(TO_TIMESTAMP(ADD (
						DIV(SUB(TO_REAL(HEX_TO_INT(Field2)), TO_REAL(116444736000000000)), TO_REAL(10000000))
						,TO_REAL(TIMESTAMP (
								'1970'
								,'yyyy'
								))
						)), 'M/d/yyyy HH:mm:ss')
		END AS DateAndTime,
	CASE TO_STRING(Field5)
		WHEN '0'
			THEN 'Information'
		WHEN '1'
			THEN 'Warning'
		WHEN '2'
			THEN 'Error'
		ELSE ''
		END AS Severity,
	CASE Field2
		WHEN 'CVE'
			THEN Field1
		WHEN 'SYLINK'
			THEN Field1
		WHEN 'Smc'
			THEN Field1
		WHEN NULL
			THEN Field1
		ELSE Field7
		END AS Summary,
	CASE Field2
		WHEN 'CVE'
			THEN Field2
		WHEN 'SYLINK'
			THEN Field2
		WHEN 'Smc'
			THEN Field2
		WHEN NULL
			THEN Field2
		ELSE Field8 
		END AS Type,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN HEX_TO_INT(SUBSTR(Field9, 2, 8))
		END AS Size_(bytes),
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE STRCAT(TO_STRING(ADD (
						HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 2, 2))
						,1
						)), STRCAT('/', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 4, 2))), STRCAT('/', STRCAT(TO_STRING(ADD (
										HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 0, 2))
										,1970
										)), STRCAT(' ', STRCAT(CASE STRLEN(TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 6, 2))))
											WHEN 1
												THEN STRCAT('0', TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 6, 2))))
											ELSE TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 6, 2)))
											END, STRCAT(':', STRCAT(CASE STRLEN(TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 8, 2))))
													WHEN 1
														THEN STRCAT('0', TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 8, 2))))
													ELSE TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 8, 2)))
													END, STRCAT(':', CASE STRLEN(TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 10, 2))))
														WHEN 1
															THEN STRCAT('0', TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 10, 2))))
														ELSE TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 0, ','), 10, 2)))
														END))))))))))
		END AS LOG:Time(UTC),
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 1, ',')
				WHEN '1'
					THEN 'IS_ALERT'
				WHEN '2'
					THEN 'SCAN_STOP'
				WHEN '3'
					THEN 'SCAN_START'
				WHEN '4'
					THEN 'PATTERN_UPDATE'
				WHEN '5'
					THEN 'INFECTION'
				WHEN '6'
					THEN 'FILE_NOTOPEN'
				WHEN '7'
					THEN 'LOAD_PATTERN'
				WHEN '8'
					THEN 'MESSAGE_INFO'
				WHEN '9'
					THEN 'MESSAGE_ERROR'
				WHEN '10'
					THEN 'CHECKSUM'
				WHEN '11'
					THEN 'TRAP'
				WHEN '12'
					THEN 'CONFIG_CHANGE'
				WHEN '13'
					THEN 'SHUTDOWN'
				WHEN '14'
					THEN 'STARTUP'
				WHEN '16'
					THEN 'PATTERN_DOWNLOAD'
				WHEN '17'
					THEN 'TOO_MANY_VIRUSES'
				WHEN '18'
					THEN 'FWD_TO_QSERVER'
				WHEN '19'
					THEN 'SCANDLVR'
				WHEN '20'
					THEN 'BACKUP'
				WHEN '21'
					THEN 'SCAN_ABORT'
				WHEN '22'
					THEN 'RTS_LOAD_ERROR'
				WHEN '23'
					THEN 'RTS_LOAD'
				WHEN '24'
					THEN 'RTS_UNLOAD'
				WHEN '25'
					THEN 'REMOVE_CLIENT'
				WHEN '26'
					THEN 'SCAN_DELAYED'
				WHEN '27'
					THEN 'SCAN_RESTART'
				WHEN '28'
					THEN 'ADD_SAVROAMCLIENT_TOSERVER'
				WHEN '29'
					THEN 'REMOVE_SAVROAMCLIENT_FROMSERVER'
				WHEN '30'
					THEN 'LICENSE_WARNING'
				WHEN '31'
					THEN 'LICENSE_ERROR'
				WHEN '32'
					THEN 'LICENSE_GRACE'
				WHEN '33'
					THEN 'UNAUTHORIZED_COMM'
				WHEN '34'
					THEN 'LOG:FWD_THRD_ERR'
				WHEN '35'
					THEN 'LICENSE_INSTALLED'
				WHEN '36'
					THEN 'LICENSE_ALLOCATED'
				WHEN '37'
					THEN 'LICENSE_OK'
				WHEN '38'
					THEN 'LICENSE_DEALLOCATED'
				WHEN '39'
					THEN 'BAD_DEFS_ROLLBACK'
				WHEN '40'
					THEN 'BAD_DEFS_UNPROTECTED'
				WHEN '41'
					THEN 'SAV_PROVIDER_PARSING_ERROR'
				WHEN '42'
					THEN 'RTS_ERROR'
				WHEN '43'
					THEN 'COMPLIANCE_FAIL'
				WHEN '44'
					THEN 'COMPLIANCE_SUCCESS'
				WHEN '45'
					THEN 'SECURITY_SYMPROTECT_POLICYVIOLATION'
				WHEN '46'
					THEN 'ANOMALY_START'
				WHEN '47'
					THEN 'DETECTIOM_ACTION_TAKEN'
				WHEN '48'
					THEN 'REMEDIATION_ACTION_PENDING'
				WHEN '49'
					THEN 'REMEDIATION_ACTION_FAILED'
				WHEN '50'
					THEN 'REMEDIATION_ACTION_SUCCESSFUL'
				WHEN '51'
					THEN 'ANOMALY_FINISH'
				WHEN '52'
					THEN 'COMMS_LOGIN_FAILED'
				WHEN '53'
					THEN 'COMMS_LOGIN_SUCCESS'
				WHEN '54'
					THEN 'COMMS_UNAUTHORIZED_COMM'
				WHEN '55'
					THEN 'CLIENT_INSTALL_AV'
				WHEN '56'
					THEN 'CLIENT_INSTALL_FW'
				WHEN '57'
					THEN 'CLIENT_UNINSTALL'
				WHEN '58'
					THEN 'CLIENT_UNINSTALL_ROLLBACK'
				WHEN '59'
					THEN 'COMMS_SERVER_GROUP_ROOT_CERT_ISSUE'
				WHEN '60'
					THEN 'COMMS_SERVER_CERT_ISSUE'
				WHEN '61'
					THEN 'COMMS_TRUSTED_ROOT_CHANGE'
				WHEN '62'
					THEN 'OMMS_SERVER_CERT_STARTUP_FAILED'
				WHEN '63'
					THEN 'CLIENT_CHECKIN'
				WHEN '64'
					THEN 'CLIENT_NO_CHECKIN'
				WHEN '65'
					THEN 'SCAN_SUSPENDED'
				WHEN '66'
					THEN 'SCAN RESUMED'
				WHEN '67'
					THEN 'SCAN_DURATION_INSUFFICIENT'
				WHEN '68'
					THEN 'CLIENT_MOVE'
				WHEN '69'
					THEN 'SCAN_FAILED_ENHANCED'
				WHEN '70'
					THEN 'COMPLIANCE_FAILEDAUDIT'
				WHEN '71'
					THEN 'HEUR_THREAT_NOW_WHITELISTED'
				WHEN '72'
					THEN 'INTERESTING_PROCESS_DETECTED_START'
				WHEN '73'
					THEN 'LOAD_ERROR_BASH'
				WHEN '74'
					THEN 'LOAD_ERROR_BASH_DEFINITIONS'
				WHEN '75'
					THEN 'INTERESTING_PROCESS_DETECTED_FINISH'
				WHEN '76'
					THEN 'BASH_NOT_SUPPORTED_FOR_OS'
				WHEN '77'
					THEN 'HEUR_THREAT_NOW_KNOWN'
				WHEN '78'
					THEN 'DISABLE_BASH'
				WHEN '79'
					THEN 'ENABLE_BASH'
				WHEN '80'
					THEN 'DEFS_LOAD_FAILED'
				WHEN '81'
					THEN 'LOCALREP_CACHE_SERVER_ERROR'
				WHEN '82'
					THEN 'REPUTATION_CHECK_TIMEOUT'
				WHEN '83'
					THEN 'SYMEPSECFILTER_DRIVER_ERROR'
				WHEN '84'
					THEN 'VSIC_COMMUNICATION_WARNING'
				WHEN '85'
					THEN 'VSIC_COMMUNICATION_RESTORED'
				WHEN '86'
					THEN 'ELAM_LOAD_FAILED'
				WHEN '87'
					THEN 'ELAM_INVALID_OS'
				WHEN '88'
					THEN 'ELAM_ENABLE'
				WHEN '89'
					THEN 'ELAM_DISABLE'
				WHEN '90'
					THEN 'ELAM_BAD'
				WHEN '91'
					THEN 'ELAM_BAD_REPORTED_AS_UNKNOWN'
				WHEN '92'
					THEN 'DISABLE_SYMPROTECT'
				WHEN '93'
					THEN 'ENABLE_SYMPROTECT'
				WHEN '94'
					THEN 'NETSEC_EOC_PARSE_FAILED'
				ELSE EXTRACT_TOKEN(Field9, 1, ',')
				END
		END AS LOG:Event,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 2, ',')
				WHEN '1'
					THEN 'Infection'
				WHEN '2'
					THEN 'Summary'
				WHEN '3'
					THEN 'Pattern'
				WHEN '4'
					THEN 'Security'
				ELSE EXTRACT_TOKEN(Field9, 2, ',')
				END
		END AS LOG:Category,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 3, ',')
				WHEN '0'
					THEN 'Scheduled'
				WHEN '1'
					THEN 'Manual'
				WHEN '2'
					THEN 'Real_Time'
				WHEN '3'
					THEN 'Integrity_Shield'
				WHEN '6'
					THEN 'Console'
				WHEN '7'
					THEN 'VPDOWN'
				WHEN '8'
					THEN 'System'
				WHEN '9'
					THEN 'Startup'
				WHEN '10'
					THEN 'Idle'
				WHEN '11'
					THEN 'DefWatch'
				WHEN '12'
					THEN 'Licensing'
				WHEN '13'
					THEN 'Manual_Quarantine'
				WHEN '14'
					THEN 'SymProtect'
				WHEN '15'
					THEN 'Reboot_Processing'
				WHEN '16'
					THEN 'Bash'
				WHEN '17'
					THEN 'SymElam'
				WHEN '18'
					THEN 'PowerEraser'
				WHEN '19'
					THEN 'EOCScan'
				WHEN '100'
					THEN 'LOCAL_END'
				WHEN '101'
					THEN 'Client'
				WHEN '102'
					THEN 'Forewarded'
				WHEN '256'
					THEN 'Transport_Client'
				ELSE EXTRACT_TOKEN(Field9, 3, ',')
				END
		END AS LOG:Logger,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 4, ',')
		END AS LOG:Computer,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 5, ',')
		END AS LOG:User,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 6, ',')
		END AS LOG:Virus,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 7, ',')
		END AS LOG:File,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 8, ',')
				WHEN '4294967295#'
					THEN 'Invalid'
				WHEN '1'
					THEN 'Quarantine'
				WHEN '2'
					THEN 'Rename'
				WHEN '3'
					THEN 'Delete'
				WHEN '4'
					THEN 'Leave Alone'
				WHEN '5'
					THEN 'Clean'
				WHEN '6'
					THEN 'Remove Macros'
				WHEN '7'
					THEN 'Save file as...'
				WHEN '8'
					THEN 'Send to backend'
				WHEN '9'
					THEN 'Restore from Quarantine'
				WHEN '10'
					THEN 'Rename Back (unused)'
				WHEN '11'
					THEN 'Undo Action'
				WHEN '12'
					THEN 'Error'
				WHEN '13'
					THEN 'Backup to quarantine (backup view)'
				WHEN '14'
					THEN 'Pending Analysis'
				WHEN '16'
					THEN 'Terminate Process Required'
				WHEN '17'
					THEN 'Exclude from Scanning'
				WHEN '18'
					THEN 'Reboot Processing'
				WHEN '19'
					THEN 'Clean by Deletion'
				WHEN '20'
					THEN 'Access Denied'
				WHEN '21'
					THEN 'TERMINATE PROCESS ONLY'
				WHEN '22'
					THEN 'NO REPAIR'
				WHEN '23'
					THEN 'FAIL'
				WHEN '24'
					THEN 'RUN POWERTOOL'
				WHEN '25'
					THEN 'NO REPAIR POWERTOOL'
				WHEN '110'
					THEN 'INTERESTING PROCESS CAL'
				WHEN '111'
					THEN 'INTERESTING PROCESS DETECTED'
				WHEN '1000'
					THEN 'INTERESTING PROCESS HASHED DETECTED'
				WHEN '1001'
					THEN 'DNS HOST FILE EXCEPTOION'
				ELSE EXTRACT_TOKEN(Field9, 8, ',')
				END
		END AS LOG:WantedAction1,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 9, ',')
				WHEN '4294967295#'
					THEN 'Invalid'
				WHEN '1'
					THEN 'Quarantine'
				WHEN '2'
					THEN 'Rename'
				WHEN '3'
					THEN 'Delete'
				WHEN '4'
					THEN 'Leave Alone'
				WHEN '5'
					THEN 'Clean'
				WHEN '6'
					THEN 'Remove Macros'
				WHEN '7'
					THEN 'Save file as...'
				WHEN '8'
					THEN 'Send to backend'
				WHEN '9'
					THEN 'Restore from Quarantine'
				WHEN '10'
					THEN 'Rename Back (unused)'
				WHEN '11'
					THEN 'Undo Action'
				WHEN '12'
					THEN 'Error'
				WHEN '13'
					THEN 'Backup to quarantine (backup view)'
				WHEN '14'
					THEN 'Pending Analysis'
				WHEN '16'
					THEN 'Terminate Process Required'
				WHEN '17'
					THEN 'Exclude from Scanning'
				WHEN '18'
					THEN 'Reboot Processing'
				WHEN '19'
					THEN 'Clean by Deletion'
				WHEN '20'
					THEN 'Access Denied'
				WHEN '21'
					THEN 'TERMINATE PROCESS ONLY'
				WHEN '22'
					THEN 'NO REPAIR'
				WHEN '23'
					THEN 'FAIL'
				WHEN '24'
					THEN 'RUN POWERTOOL'
				WHEN '25'
					THEN 'NO REPAIR POWERTOOL'
				WHEN '110'
					THEN 'INTERESTING PROCESS CAL'
				WHEN '111'
					THEN 'INTERESTING PROCESS DETECTED'
				WHEN '1000'
					THEN 'INTERESTING PROCESS HASHED DETECTED'
				WHEN '1001'
					THEN 'DNS HOST FILE EXCEPTOION'
				ELSE EXTRACT_TOKEN(Field9, 9, ',')
				END
		END AS LOG:WantedAction2,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 10, ',')
				WHEN '4294967295#'
					THEN 'Invalid'
				WHEN '1'
					THEN 'Quarantine'
				WHEN '2'
					THEN 'Rename'
				WHEN '3'
					THEN 'Delete'
				WHEN '4'
					THEN 'Leave Alone'
				WHEN '5'
					THEN 'Clean'
				WHEN '6'
					THEN 'Remove Macros'
				WHEN '7'
					THEN 'Save file as...'
				WHEN '8'
					THEN 'Send to backend'
				WHEN '9'
					THEN 'Restore from Quarantine'
				WHEN '10'
					THEN 'Rename Back (unused)'
				WHEN '11'
					THEN 'Undo Action'
				WHEN '12'
					THEN 'Error'
				WHEN '13'
					THEN 'Backup to quarantine (backup view)'
				WHEN '14'
					THEN 'Pending Analysis'
				WHEN '16'
					THEN 'Terminate Process Required'
				WHEN '17'
					THEN 'Exclude from Scanning'
				WHEN '18'
					THEN 'Reboot Processing'
				WHEN '19'
					THEN 'Clean by Deletion'
				WHEN '20'
					THEN 'Access Denied'
				WHEN '21'
					THEN 'TERMINATE PROCESS ONLY'
				WHEN '22'
					THEN 'NO REPAIR'
				WHEN '23'
					THEN 'FAIL'
				WHEN '24'
					THEN 'RUN POWERTOOL'
				WHEN '25'
					THEN 'NO REPAIR POWERTOOL'
				WHEN '110'
					THEN 'INTERESTING PROCESS CAL'
				WHEN '111'
					THEN 'INTERESTING PROCESS DETECTED'
				WHEN '1000'
					THEN 'INTERESTING PROCESS HASHED DETECTED'
				WHEN '1001'
					THEN 'DNS HOST FILE EXCEPTOION'
				ELSE EXTRACT_TOKEN(Field9, 10, ',')
				END
		END AS LOG:RealAction,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 11, ',')
				WHEN '48'
					THEN 'Heuristic'
				WHEN '64'
					THEN 'Reputation'
				WHEN '80'
					THEN 'Hack Tools'
				WHEN '96'
					THEN 'Spyware'
				WHEN '112'
					THEN 'Trackware'
				WHEN '128'
					THEN 'Dialers'
				WHEN '144'
					THEN 'Remote Access'
				WHEN '160'
					THEN 'Adware'
				WHEN '176'
					THEN 'Joke Programs'
				WHEN '224'
					THEN 'Heuristic Application'
				ELSE EXTRACT_TOKEN(Field9, 11, ',')
				END
		END AS LOG:Virus_Type,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 12, ',')
		END AS LOG:Flags,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 13, ',')
		END AS LOG:Description,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 14, ',')
		END AS LOG:ScanID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 15, ',')
		END AS LOG:New_Ext,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 16, ',')
		END AS LOG:Group_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 17, ',')
		END AS LOG:Event_Data,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 18, ',')
		END AS LOG:VBin_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 19, ',')
		END AS LOG:Virus_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 20, ',')
		END AS LOG:Quarantine_Forward_Status,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 21, ',')
		END AS LOG:Access,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 22, ',')
		END AS LOG:SDN_Status,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 23, ',')
		END AS LOG:Compressed,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 24, ',')
		END AS LOG:Depth,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 25, ',')
		END AS LOG:Still_Infected,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 26, ',')
		END AS LOG:Def_Info,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 27, ',')
		END AS LOG:Def_Sequence_Number,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 28, ',')
		END AS LOG:Clean_Info,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 29, ',')
		END AS LOG:Delete_Info,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 30, ',')
		END AS LOG:Backup_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 31, ',')
		END AS LOG:Parent,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 32, ',')
		END AS LOG:GUID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 33, ',')
		END AS LOG:Client_Group,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 34, ',')
		END AS LOG:Address,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 35, ',')
		END AS LOG:Domain_Name,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 36, ',')
		END AS LOG:NT_Domain,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 37, ',')
		END AS LOG:MAC_Address,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 38, ',')
		END AS LOG:Version,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 39, ',')
		END AS LOG:Remote_Machine,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 40, ',')
		END AS LOG:Remote_Machine_IP,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 41, ',')
		END AS LOG:Action_1_Status,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 42, ',')
		END AS LOG:Action_2_Status,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 43, ',')
		END AS LOG:License_Feature_Name,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 44, ',')
		END AS LOG:License_Feature_Version,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 45, ',')
		END AS LOG:License_Serial_Number,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 46, ',')
		END AS LOG:License_Fulfillment_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 47, ',')
		END AS LOG:License_Start_Date,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 48, ',')
		END AS LOG:License_Expiration_Date,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 49, ',')
		END AS LOG:License_LifeCycle,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 50, ',')
		END AS LOG:License_Seats_Total,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 51, ',')
		END AS LOG:License_Seats,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 52, ',')
		END AS LOG:Error_Code,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 53, ',')
		END AS LOG:License_Seats_Delta,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 54, ',')
		END AS LOG:Status,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 55, ',')
		END AS LOG:Domain_GUID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 56, ',')
		END AS LOG:LOG:Session_GUID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 57, ',')
		END AS LOG:VBin_Session_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 58, ',')
		END AS LOG:Login_Domain,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 59, ',')
		END AS LOG:Event_Data_2,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 60, ',')
				WHEN '1'
					THEN 'HeuristicTrojanWorm'
				WHEN '2'
					THEN 'HeuristicKeyLogger'
				WHEN '100'
					THEN 'CommercialRemoteControl'
				WHEN '101'
					THEN 'CommercialKeyLogger'
				WHEN '200'
					THEN 'Cookie'
				WHEN '300'
					THEN 'Shields'
				END
		END AS LOG:Eraser_Category_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 61, ',')
				WHEN '1'
					THEN 'MALWARE'
				WHEN '2'
					THEN 'SECURITY_RISK'
				WHEN '3'
					THEN 'POTENTIALLY_UNWANTED_APPLICATIONS'
				WHEN '4'
					THEN 'EXPERIMENTAL_HEURISTIC'
				WHEN '5'
					THEN 'LEGACY_VIRAL'
				WHEN '6'
					THEN 'LEGACY_NON_VIRAL'
				WHEN '7'
					THEN 'VATEGORY_CRIMEWARE'
				WHEN '8'
					THEN 'ADVANCED_HEURISTICS'
				WHEN '9'
					THEN 'REPUTATION_BACKED_ADVANCED_HEURISTICS'
				WHEN '10'
					THEN 'PREVALENCE_BACKED_ADVANCED_HEURISTICS'
				END
		END AS LOG:Dynamic_Categoryset_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 62, ',')
		END AS LOG:Subcategoryset_ID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 63, ',')
				WHEN '0'
					THEN 'Application Name'
				WHEN '1'
					THEN 'VID Virus Name'
				END
		END AS LOG:Display_Name_To_Use,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 64, ',')
				WHEN '0'
					THEN 'Good'
				WHEN '1'
					THEN 'Bad'
				WHEN '127'
					THEN 'Unknown'
				END
		END AS LOG:Reputation_Disposition,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 65, ',')
		END AS LOG:Reputation_Confidence,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 66, ',')
		END AS LOG:First_Seen,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 67, ',')
		END AS LOG:Reputation_Prevalence,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 68, ',')
		END AS LOG:Downloaded_URL,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 69, ',')
		END AS LOG:Creator_For_Dropper,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 70, ',')
		END AS LOG:CIDS_State,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 71, ',')
		END AS LOG:Behavior_Risk_Level,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 72, ',')
				WHEN '0'
					THEN 'Traditional'
				WHEN '1'
					THEN 'Heuristic'
				END
		END AS LOG:Detection_Type,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 73, ',')
		END AS LOG:Acknowledge_Text,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 74, ',')
				WHEN '0'
					THEN 'Off'
				WHEN '1'
					THEN 'On'
				WHEN ''
					THEN 'Failed'
				END
		END AS LOG:VSIC_State,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 75, ',')
		END AS LOG:Scan_GUID,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 76, ',')
		END AS LOG:Scan_Duration,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE STRCAT(TO_STRING(ADD (
						HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 2, 2))
						,1
						)), STRCAT('/', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 4, 2))), STRCAT('/', STRCAT(TO_STRING(ADD (
										HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 0, 2))
										,1970
										)), STRCAT(' ', STRCAT(CASE STRLEN(TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 6, 2))))
											WHEN 1
												THEN STRCAT('0', TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 6, 2))))
											ELSE TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 6, 2)))
											END, STRCAT(':', STRCAT(CASE STRLEN(TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 8, 2))))
													WHEN 1
														THEN STRCAT('0', TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 8, 2))))
													ELSE TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 8, 2)))
													END, STRCAT(':', CASE STRLEN(TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 10, 2))))
														WHEN 1
															THEN STRCAT('0', TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 10, 2))))
														ELSE TO_STRING(HEX_TO_INT(SUBSTR(EXTRACT_TOKEN(Field9, 77, ','), 10, 2)))
														END))))))))))
		END AS LOG:Scan_Start_Time,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE CASE EXTRACT_TOKEN(Field9, 78, ',')
				WHEN '0'
					THEN 'Normal'
				WHEN '1'
					THEN 'Modern (Metro)'
				END
		END AS LOG:TargetApp,
	CASE DIV(STRLEN(Field9), 11)
		WHEN 1
			THEN ''
		WHEN NULL
			THEN ''
		ELSE EXTRACT_TOKEN(Field9, 79, ',')
		END AS LOG:Scan_Command_GUID
INTO '%destinationDirectory%\Symantec_System_Logs.csv'
FROM '%sourceFile%'
WHERE Summary NOT IN ('Smc')
