function New-RandomPassword
{
	<#
	.SYNOPSIS
		Generates a new strong random password
	
	.DESCRIPTION
	
		Flexible function to generate random passowrds of 
		variable length using the RNGCryptoServiceProvider
		to add as much enthropy as possible.
		
		By default function will print both the final password
		and phoenitc version of it making  it easier for an operator 
		to read/communicate it verbally.
		
		If no parameters are specified a 12 characters long
		password will be generated.
	
	.PARAMETER PasswordLength
		Specifies the number of characters composing the
		password.
		
		Cannot be used in conjuction with other parameters.
	
	.PARAMETER LowerCaseLetters
		Specifies the number of lowercase letters that
		should be used in the password.
		
		Cannot be used in conjuction with the PasswordLength
		parameter.
	
	.PARAMETER CapitalCaseLetters
		Specifies the number of uppercase letters that
		should be used in the password.
		
		Cannot be used in conjuction with the PasswordLength
		parameter.
	
	.PARAMETER NumberDigits
		Specifies the number of digits (numbers) that
		should be used in the password.
		
		Cannot be used in conjuction with the PasswordLength
		parameter.
	
	.PARAMETER Symbol
		Specifies the number of symbols (special characters) that
		should be used in the password.
		
		Cannot be used in conjuction with the PasswordLength
		parameter.
	
	.PARAMETER ColorOutput
		Defaults to $false will simply print phonetic output
		in green color
	
	.PARAMETER PasswordToClipboard
		If specified parameter will automatically copy generated
		password to Clipboard.
		
		If running PowerShell 5.0 or above default Set-ClipBoard
		cmdlet will be used otherwise built-in utility clip.exe
		will be used.
	
	.EXAMPLE
	
		-------------------------- EXAMPLE 1 --------------------------
	
		PS C:\> New-RandomPassword
	
		Character Phonetic            Type
		--------- --------            ----
		,         Comma               Symbol
		W         Whiskey             Capital Letter
		<         Less than sign      Symbol
		b         Bravo               Lowercase Letter
		s         Sierra              Lowercase Letter
		#         Hash sign           Symbol
		)         Closing parenthesis Symbol
		E         Echo                Capital Letter
		p         Papa                Lowercase Letter
		W         Whiskey             Capital Letter
		C         Charlie             Capital Letter
		v         Victor              Lowercase Letter
		
		Final password is: ,W<bs#)EpWCv
	
	 	Description
    	-----------

    	Generates a new random password using the default length
	
		-------------------------- EXAMPLE 2 --------------------------
	
		PS C:\> New-StrongPassword -CapitalCaseLetters 6 -LowerCaseLetters 6
		
		Character Phonetic Type
		--------- -------- ----
		e         Echo     Lowercase Letter
		V         Victor   Capital Letter
		G         Golf     Capital Letter
		f         Foxtrot  Lowercase Letter
		a         Alpha    Lowercase Letter
		s         Sierra   Lowercase Letter
		M         Mike     Capital Letter
		X         X-Ray    Capital Letter
		f         Foxtrot  Lowercase Letter
		S         Sierra   Capital Letter
		P         Papa     Capital Letter
		d         Delta    Lowercase Letter
		
		
		Final password is: eVGfasMXfSPd
	
	 	Description
    	-----------

    	Generates a new random password composed of 6 uppercase letters
		and 6 lowercase letters
	
		-------------------------- EXAMPLE 3 --------------------------
	
		PS C:\> New-StrongPassword -CapitalCaseLetters 6 -LowerCaseLetters 6 -Symbol 3

		Character Phonetic  Type
		--------- --------  ----
		G         Golf      Capital Letter
		Z         Zulu      Capital Letter
		&         Ampersand Symbol
		L         Lima      Capital Letter
		u         Uniform   Lowercase Letter
		Q         Quebec    Capital Letter
		i         India     Lowercase Letter
		s         Sierra    Lowercase Letter
		y         Yankee    Lowercase Letter
		:         Colon     Symbol
		c         Charlie   Lowercase Letter
		@         At symbol Symbol
		O         Oscar     Capital Letter
		t         Tango     Lowercase Letter
		P         Papa      Capital Letter
		
		Final password is: GZ&LuQisy:c@OtP
	
	 	Description
    	-----------

    	Similar to Example 2 just will generate a password containing 3 symbols in
		addition to 6 Uppercase letters and 6 Lowercase letters
	#>
	
	[CmdletBinding(DefaultParameterSetName = 'Default',
				   ConfirmImpact = 'Medium',
				   PositionalBinding = $true,
				   SupportsShouldProcess = $true)]
	[OutputType([string])]
	param
	(
		[Parameter(ParameterSetName = 'Default',
				   Mandatory = $false,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0,
				   HelpMessage = 'Specifies password length')]
		[ValidateNotNull()]
		[Alias('length')]
		[int]
		$PasswordLength = 12,
		[Parameter(ParameterSetName = 'Option',
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0)]
		[ValidateNotNull()]
		[Alias('LowerCase', 'Small')]
		[int]
		$LowerCaseLetters = 0,
		[Parameter(ParameterSetName = 'Option',
				   ValueFromPipelineByPropertyName = $true,
				   Position = 1)]
		[ValidateNotNull()]
		[Alias('UpperCase', 'Capital')]
		[int]
		$CapitalCaseLetters = 0,
		[Parameter(ParameterSetName = 'Option',
				   ValueFromPipelineByPropertyName = $true,
				   Position = 2)]
		[ValidateNotNull()]
		[int]
		$NumberDigits = 0,
		[Parameter(ParameterSetName = 'Option',
				   ValueFromPipelineByPropertyName = $true,
				   Position = 3)]
		[ValidateNotNull()]
		[Alias('SpecialLetter')]
		[int]
		$Symbol = 0,
		[Parameter(ParameterSetName = 'Option',
				   Position = 4)]
		[Parameter(ParameterSetName = 'Default')]
		[switch]
		$ColorOutput,
		[Parameter(Position = 5)]
		[switch]
		$PasswordToClipboard
	)
	
	Begin
	{
		$tempRandomPassword = @()
		$returnPassword = @()
		$returnLowerCasePassword = @()
		$returnCapitalCasePassword = @()
		$returnSymbolPassword = @()
		$returnDigitsPassword = @()
		
		# Generate Json AsciiCodes table
		<# 
		Excluded Codes:
		{"Index":  "28","Number":  "96","AsciiCode":  "`","Phonetic":  "Grave accent","Type":  "Symbol"},
		{ "Index": "32", "Number": "126", "AsciiCode": "~", "Phonetic": "Equivalency sign - Tilde", "Type": "Symbol" },
		#>
		
		[string]$asciiJson = @"
    [
        {"Index": "1","Number": "33","AsciiCode": "!","Phonetic": "Exclamation point","Type": "Symbol"},
        {"Index": "2","Number": "34","AsciiCode": "\"","Phonetic":"Double quotes","Type": "Symbol"},
        {"Index": "3","Number": "35","AsciiCode": "#","Phonetic": "Hash sign","Type": "Symbol"},
        {"Index": "4","Number": "36","AsciiCode": "$","Phonetic": "Dollar sign","Type": "Symbol"},
        {"Index": "5","Number": "37","AsciiCode": "%","Phonetic": "Percent sign","Type": "Symbol"},
        {"Index": "6","Number": "38","AsciiCode": "&","Phonetic": "Ampersand","Type": "Symbol"},
        {"Index": "7","Number": "39","AsciiCode": "'","Phonetic": "Single quote","Type": "Symbol"},
        {"Index": "8","Number": "40","AsciiCode": "(","Phonetic": "Opening parenthesis","Type": "Symbol"},
        {"Index": "9","Number": "41","AsciiCode": ")","Phonetic": "Closing parenthesis","Type": "Symbol"},
        {"Index": "10","Number": "42","AsciiCode": "*","Phonetic": "Asterisk","Type": "Symbol"},
        {"Index": "11","Number": "43","AsciiCode": "+","Phonetic": "Plus sign","Type": "Symbol"},
        {"Index": "12","Number": "44","AsciiCode": ",","Phonetic": "Comma","Type": "Symbol"},
        {"Index": "13","Number": "45","AsciiCode": "-","Phonetic": "Minus sign -Hyphen","Type": "Symbol"},
        {"Index": "14","Number": "46","AsciiCode": ".","Phonetic": "Period","Type": "Symbol"},
        {"Index": "15","Number": "47","AsciiCode": "/","Phonetic": "Slash","Type": "Symbol"},
        {"Index": "16","Number": "58","AsciiCode": ":","Phonetic": "Colon","Type": "Symbol"},
        {"Index": "17","Number": "59","AsciiCode": ";","Phonetic": "SemiColon","Type": "Symbol"},
        {"Index": "18","Number": "60","AsciiCode": "<","Phonetic": "Less than sign","Type": "Symbol"},
        {"Index": "19","Number": "61","AsciiCode": "=","Phonetic": "Equal sign","Type": "Symbol"},
        {"Index": "20","Number": "62","AsciiCode": ">","Phonetic": "Greater than sign","Type": "Symbol"},
        {"Index": "21","Number": "63","AsciiCode": "?","Phonetic": "Question mark","Type": "Symbol"},
        {"Index": "22","Number": "64","AsciiCode": "@","Phonetic": "At symbol","Type": "Symbol"},
        {"Index": "23","Number": "91","AsciiCode": "[","Phonetic": "Opening bracket","Type": "Symbol"},
        {"Index": "24","Number": "92","AsciiCode": "\\","Phonetic": "Backslash","Type": "Symbol"},
        {"Index": "25","Number": "93","AsciiCode": "]","Phonetic": "Closing bracket","Type": "Symbol"},
        {"Index": "26","Number": "94","AsciiCode": "^","Phonetic": "Caret - circumflex","Type": "Symbol"},
        {"Index": "27","Number": "95","AsciiCode": "_","Phonetic": "Underscore","Type": "Symbol"},
        {"Index": "29","Number": "123","AsciiCode": "{","Phonetic": "Opening brace","Type": "Symbol"},
        {"Index": "30","Number": "124","AsciiCode": "|","Phonetic": "Vertical bar","Type": "Symbol"},
        {"Index": "31","Number": "125","AsciiCode": "}","Phonetic": "Closing brace","Type": "Symbol"},
        {"Index": "33","Number": "65","AsciiCode": "A","Phonetic": "Alpha ","Type": "Capital Letter"},
        {"Index": "34","Number": "66","AsciiCode": "B","Phonetic": "Bravo ","Type": "Capital Letter"},
        {"Index": "35","Number": "67","AsciiCode": "C","Phonetic": "Charlie ","Type": "Capital Letter"},
        {"Index": "36","Number": "68","AsciiCode": "D","Phonetic": "Delta ","Type": "Capital Letter"},
        {"Index": "37","Number": "69","AsciiCode": "E","Phonetic": "Echo ","Type": "Capital Letter"},
        {"Index": "38","Number": "70","AsciiCode": "F","Phonetic": "Foxtrot ","Type": "Capital Letter"},
        {"Index": "39","Number": "71","AsciiCode": "G","Phonetic": "Golf ","Type": "Capital Letter"},
        {"Index": "40","Number": "72","AsciiCode": "H","Phonetic": "Hotel ","Type": "Capital Letter"},
        {"Index": "41","Number": "73","AsciiCode": "I","Phonetic": "India ","Type": "Capital Letter"},
        {"Index": "42","Number": "74","AsciiCode": "J","Phonetic": "Juliet ","Type": "Capital Letter"},
        {"Index": "43","Number": "75","AsciiCode": "K","Phonetic": "Kilo ","Type": "Capital Letter"},
        {"Index": "44","Number": "76","AsciiCode": "L","Phonetic": "Lima ","Type": "Capital Letter"},
        {"Index": "45","Number": "77","AsciiCode": "M","Phonetic": "Mike ","Type": "Capital Letter"},
        {"Index": "46","Number": "78","AsciiCode": "N","Phonetic": "November ","Type": "Capital Letter"},
        {"Index": "47","Number": "79","AsciiCode": "O","Phonetic": "Oscar ","Type": "Capital Letter"},
        {"Index": "48","Number": "80","AsciiCode": "P","Phonetic": "Papa ","Type": "Capital Letter"},
        {"Index": "49","Number": "81","AsciiCode": "Q","Phonetic": "Quebec ","Type": "Capital Letter"},
        {"Index": "50","Number": "82","AsciiCode": "R","Phonetic": "Romeo ","Type": "Capital Letter"},
        {"Index": "51","Number": "83","AsciiCode": "S","Phonetic": "Sierra ","Type": "Capital Letter"},
        {"Index": "52","Number": "84","AsciiCode": "T","Phonetic": "Tango ","Type": "Capital Letter"},
        {"Index": "53","Number": "85","AsciiCode": "U","Phonetic": "Uniform ","Type": "Capital Letter"},
        {"Index": "54","Number": "86","AsciiCode": "V","Phonetic": "Victor ","Type": "Capital Letter"},
        {"Index": "55","Number": "87","AsciiCode": "W","Phonetic": "Whiskey ","Type": "Capital Letter"},
        {"Index": "56","Number": "88","AsciiCode": "X","Phonetic": "X-Ray ","Type": "Capital Letter"},
        {"Index": "57","Number": "89","AsciiCode": "Y","Phonetic": "Yankee ","Type": "Capital Letter"},
        {"Index": "58","Number": "90","AsciiCode": "Z","Phonetic": "Zulu ","Type": "Capital Letter"},
        {"Index": "59","Number": "97","AsciiCode": "a","Phonetic": "Alpha ","Type": "Lowercase Letter"},
        {"Index": "60","Number": "98","AsciiCode": "b","Phonetic": "Bravo ","Type": "Lowercase Letter"},
        {"Index": "61","Number": "99","AsciiCode": "c","Phonetic": "Charlie ","Type": "Lowercase Letter"},
        {"Index": "62","Number": "100","AsciiCode": "d","Phonetic": "Delta ","Type": "Lowercase Letter"},
        {"Index": "63","Number": "101","AsciiCode": "e","Phonetic": "Echo ","Type": "Lowercase Letter"},
        {"Index": "64","Number": "102","AsciiCode": "f","Phonetic": "Foxtrot ","Type": "Lowercase Letter"},
        {"Index": "65","Number": "103","AsciiCode": "g","Phonetic": "Golf ","Type": "Lowercase Letter"},
        {"Index": "66","Number": "104","AsciiCode": "h","Phonetic": "Hotel ","Type": "Lowercase Letter"},
        {"Index": "67","Number": "105","AsciiCode": "i","Phonetic": "India ","Type": "Lowercase Letter"},
        {"Index": "68","Number": "106","AsciiCode": "j","Phonetic": "Juliet ","Type": "Lowercase Letter"},
        {"Index": "69","Number": "107","AsciiCode": "k","Phonetic": "Kilo ","Type": "Lowercase Letter"},
        {"Index": "70","Number": "108","AsciiCode": "l","Phonetic": "Lima ","Type": "Lowercase Letter"},
        {"Index": "71","Number": "109","AsciiCode": "m","Phonetic": "Mike ","Type": "Lowercase Letter"},
        {"Index": "72","Number": "110","AsciiCode": "n","Phonetic": "November ","Type": "Lowercase Letter"},
        {"Index": "73","Number": "111","AsciiCode": "o","Phonetic": "Oscar ","Type": "Lowercase Letter"},
        {"Index": "74","Number": "112","AsciiCode": "p","Phonetic": "Papa ","Type": "Lowercase Letter"},
        {"Index": "75","Number": "113","AsciiCode": "q","Phonetic": "Quebec ","Type": "Lowercase Letter"},
        {"Index": "76","Number": "114","AsciiCode": "r","Phonetic": "Romeo ","Type": "Lowercase Letter"},
        {"Index": "77","Number": "115","AsciiCode": "s","Phonetic": "Sierra ","Type": "Lowercase Letter"},
        {"Index": "78","Number": "116","AsciiCode": "t","Phonetic": "Tango ","Type": "Lowercase Letter"},
        {"Index": "79","Number": "117","AsciiCode": "u","Phonetic": "Uniform ","Type": "Lowercase Letter"},
        {"Index": "80","Number": "118","AsciiCode": "v","Phonetic": "Victor ","Type": "Lowercase Letter"},
        {"Index": "81","Number": "119","AsciiCode": "w","Phonetic": "Whiskey ","Type": "Lowercase Letter"},
        {"Index": "82","Number": "120","AsciiCode": "x","Phonetic": "X-Ray ","Type": "Lowercase Letter"},
        {"Index": "83","Number": "121","AsciiCode": "y","Phonetic": "Yankee ","Type": "Lowercase Letter"},
        {"Index": "84","Number": "122","AsciiCode": "z","Phonetic": "Zulu ","Type": "Lowercase Letter"},
        {"Index": "85","Number": "48","AsciiCode": "0","Phonetic": "Zero","Type": "Number"},
        {"Index": "86","Number": "49","AsciiCode": "1","Phonetic": "One","Type": "Number"},
        {"Index": "87","Number": "50","AsciiCode": "2","Phonetic": "Two","Type": "Number"},
        {"Index": "88","Number": "51","AsciiCode": "3","Phonetic": "Three","Type": "Number"},
        {"Index": "89","Number": "52","AsciiCode": "4","Phonetic": "Four","Type": "Number"},
        {"Index": "90","Number": "53","AsciiCode": "5","Phonetic": "Five","Type": "Number"},
        {"Index": "91","Number": "54","AsciiCode": "6","Phonetic": "Six","Type": "Number"},
        {"Index": "92","Number": "55","AsciiCode": "7","Phonetic": "Seven","Type": "Number"},
        {"Index": "93","Number": "56","AsciiCode": "8","Phonetic": "Eight","Type": "Number"},
        {"Index": "94","Number": "57","AsciiCode": "9","Phonetic": "Nine","Type": "Number"}
    ]
"@
		# Generate Seed
		function Get-RandomSeed
		{
			# Instantiate object
			$randomBytes = New-Object -TypeName 'System.Byte[]' 64
			
			# Use RNGCryptoServiceProvider for better entropy
			[System.Security.Cryptography.RNGCryptoServiceProvider]$Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
			$Random.GetBytes($randomBytes)
			[BitConverter]::ToInt32($randomBytes, 0)
		}
	}
	Process
	{
		# Generate characters tables
		$charsTable = ConvertFrom-Json -InputObject $asciiJson
		$symbolsTable = $charsTable | Where-Object { $_.Type -eq 'Symbol' }
		$capitalLettersTable = $charsTable | Where-Object { $_.Type -eq 'Capital Letter' }
		$lowerCaseLettersTable = $charsTable | Where-Object { $_.Type -eq 'Lowercase Letter' }
		$digitsTable = $charsTable | Where-Object { $_.Type -eq 'Number' }
		
		switch ($PsCmdlet.ParameterSetName)
		{
			'Default'
			{
				for ($passwordLengthIdex = 1; $passwordLengthIdex -le $PasswordLength; $passwordLengthIdex++)
				{
					$seedNumber = Get-RandomSeed
					$passwordSalt = Get-Random -InputObject $charsTable -SetSeed $seedNumber
					$returnPassword += $passwordSalt
				}
			}
			'Option'
			{
				if ($LowerCaseLetters -ne 0)
				{
					for ($lowerCaseLetterIndex = 1; $lowerCaseLetterIndex -le $LowerCaseLetters; $lowerCaseLetterIndex++)
					{
						$lowerCaseSeed = Get-RandomSeed
						$returnLowerCasePassword += Get-Random -InputObject $lowerCaseLettersTable -SetSeed $lowerCaseSeed
					}
				}
				
				if ($CapitalCaseLetters -ne 0)
				{
					for ($capitalLetterIndex = 1; $capitalLetterIndex -le $CapitalCaseLetters; $capitalLetterIndex++)
					{
						$capitalCaseSeed = Get-RandomSeed
						$returnCapitalCasePassword += Get-Random -InputObject $capitalLettersTable -SetSeed $capitalCaseSeed
					}
				}
				
				if ($NumberDigits -ne 0)
				{
					for ($numberDigitsIndex = 1; $numberDigitsIndex -le $NumberDigits; $numberDigitsIndex++)
					{
						$numberDigitSeed = Get-RandomSeed
						$returnDigitsPassword += Get-Random -InputObject $digitsTable -SetSeed $numberDigitSeed
					}
				}
				
				if ($Symbol -ne 0)
				{
					for ($sy = 1; $sy -le $Symbol; $sy++)
					{
						$SymbolUniqueNumber = Get-RandomSeed
						$returnSymbolPassword += Get-Random -InputObject $symbolsTable -SetSeed $SymbolUniqueNumber
					}
				}
				
				# Concatenate passwords
				$tempRandomPassword += $returnLowerCasePassword + $returnCapitalCasePassword + $returnDigitsPassword + $returnSymbolPassword
				
				# String scamble
				$returnPassword = $tempRandomPassword |
				Select-Object '*', @{
					N    = 'Sort'; E = {
						1 .. 500 |
						Get-Random (Get-RandomSeed)
					}
				} |
				Sort-Object -Property Sort
			}
		}
	}
	End
	{
		# Format string for output
		$finalPassword = $returnPassword.AsciiCode -Join ''
		$spellOutTable = $returnPassword |
		Select-Object @{
			Name   = 'Character'; Expression = { $_.'AsciiCode' }
		}, 'Phonetic', 'Type'
		
		# Send password to clipboard
		if ($PasswordToClipboard)
		{
			$poshVersion = $PSVersionTable.PSVersion.Major
			
			# Check PoSh version
			switch ($poshVersion)
			{
				5
				{
					$finalPassword | Set-Clipboard
					break
				}
				default
				{
					$finalPassword | clip
					break
				}
			}
		}
		
		# Colored output
		if ($ColorOutput)
		{
			Write-Host ($spellOutTable | Out-String) -ForegroundColor 'Green'
			Write-Host $finalPassword
		}
		else
		{
			Write-Host ($spellOutTable | Out-String)
			Write-Host "Final password is:" $finalPassword
		}
		
		return $finalPassword
	}
}