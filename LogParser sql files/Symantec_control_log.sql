/* -headerRow:off -nSkipLines:1 -nFields:28 */
SELECT FileName,
	TO_TIMESTAMP(ADD (
			DIV(SUB(TO_REAL(HEX_TO_INT(Field10)), TO_REAL(116444736000000000)), TO_REAL(10000000))
			,TO_REAL(TIMESTAMP (
					'1970'
					,'yyyy'
					))
			)) AS DateAndTime,
	HEX_TO_INT(Field4) AS Severity,
	CASE TO_STRING(Field5)
		WHEN '3'
			THEN 'Continue'
		WHEN '1'
			THEN 'Block'
		ELSE TO_STRING(Field5)
		END AS Action,
	Field7 AS Description,
	Field8 AS API,
	Field12 AS RuleName,
	STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(Field23), 0, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(Field23), 2, 2))), STRCAT('.', STRCAT(TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(Field23), 4, 2))), STRCAT('.', TO_STRING(HEX_TO_INT(SUBSTR(HEX_TO_HEX32(Field23), 6, 2))))))))) AS IPAddress,
	HEX_TO_INT(TO_STRING(Field13)) AS CallerProcessID,
	Field14 AS CallerProcess,
	Field24 AS DeviceInstanceID,
	Field17 AS Target,
	Field19 AS USER,
	Field20 AS UserDomain,
	Field18 AS Location,
	TO_TIMESTAMP(ADD (
			DIV(SUB(TO_REAL(HEX_TO_INT(Field11)), TO_REAL(116444736000000000)), TO_REAL(10000000))
			,TO_REAL(TIMESTAMP (
					'1970'
					,'yyyy'
					))
			)) AS StartTime,
	TO_TIMESTAMP(ADD (
			DIV(SUB(TO_REAL(HEX_TO_INT(Field2)), TO_REAL(116444736000000000)), TO_REAL(10000000))
			,TO_REAL(TIMESTAMP (
					'1970'
					,'yyyy'
					))
			)) AS EndTime,
	Field16 AS ModuleName
INTO '%destinationDirectory%\Symantec_Control_Logs.csv'
FROM '%sourceFile%'
WHERE Field23 IS NOT NULL
	AND Field28 IS NULL
ORDER BY DateAndTime DESC
