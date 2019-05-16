SELECT '%FileName%' AS FileName,
	TO_TIMESTAMP(ADD (
			DIV(TO_REAL(HEX_TO_INT(Field2)), TO_REAL(10000000))
			,TO_REAL(TIMESTAMP (
					'1601'
					,'yyyy'
					))
			)) AS Date_and_Time,
	CASE TO_STRING(Field4)
		WHEN '3'
			THEN 'Critical'
		WHEN '7'
			THEN 'Major'
		ELSE TO_STRING(Field4)
		END AS Severity,
	CASE TO_STRING(Field9)
		WHEN '2'
			THEN 'Outgoing'
		WHEN '1'
			THEN 'Incoming'
		END AS Direction,
	REVERSEDNS(STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field6)), 0, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field6)), 2, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field6)), 4, 2))), STRCAT('.', TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field6)), 6, 2)))))))))) AS Remote_Host_Name, 
	STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field6)), 0, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field6)), 2, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field6)), 4, 2))), STRCAT('.', TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field6)), 6, 2))))))))) AS Remote_Host_IP, 
	HEX_TO_INT(TO_STRING(Field27)) AS Remote_Port,
	REVERSEDNS(STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field5)), 0, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field5)), 2, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field5)), 4, 2))), STRCAT('.', TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field5)), 6, 2)))))))))) AS Local_Host_Name, 
	STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field5)), 0, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field5)), 2, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field5)), 4, 2))), STRCAT('.', TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(TO_STRING(Field5)), 6, 2))))))))) AS Local_Host_IP, 
	HEX_TO_INT(Field28) AS Local_Port,
	Field16 AS Application,
	HEX_TO_INT(Field23) AS Signature_ID,
	HEX_TO_INT(Field24) AS Signature_SubID,
	Field31 AS Signature_Name,
	Field32 AS Intrusion-URL,
	Field21 AS User,
	Field22 AS User_Domain,
	Field20 AS Location,
	TO_INT(Field12) AS Occurrences,
	TO_TIMESTAMP(ADD (
			DIV(TO_REAL(HEX_TO_INT(Field11)), TO_REAL(10000000))
			,TO_REAL(TIMESTAMP (
					'1601'
					,'yyyy'
					))
			)) AS Beginning_Time,
	TO_TIMESTAMP(ADD (
			DIV(TO_REAL(HEX_TO_INT(Field10)), TO_REAL(10000000))
			,TO_REAL(TIMESTAMP (
					'1601'
					,'yyyy'
					))
			)) AS End_Time,
	Field39 AS SHA-256,
	Field14 AS Description
INTO '%destinationDirectory%\Symantec_Security_Logs.csv'
FROM '%sourceFile%'
