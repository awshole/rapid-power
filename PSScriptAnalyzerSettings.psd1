@{
    IncludeRules = @('AvoidAssignmentToAutomaticVariable',
        'AvoidDefaultValueForMandatoryParameter',
        'AvoidDefaultValueSwitchParameter',
        'AvoidLongLines',
        'AvoidOverwritingBuiltInCmdlets',
        'AvoidUsingDoubleQuotesForConstantString',
        'AvoidUsingCmdletAliases',
        'AvoidUsingComputerNameHardcoded',
        'AvoidUsingConvertToSecureStringWithPlainText', #https://github.com/PowerShell/PSScriptAnalyzer/blob/master/RuleDocumentation/AvoidUsingConvertToSecureStringWithPlainText.md
        'AvoidUsingEmptyCatchBlock',
        'AvoidUsingInvokeExpression',
        'AvoidUsingPlainTextForPassword',
        'AvoidUsingPositionalParameters',
        'AvoidTrailingWhitespace',
        'AvoidUsingUsernameAndPasswordParams',
        'AvoidUsingWriteHost',        
        'MisleadingBacktick',
        'PossibleIncorrectComparisonWithNull',
        'PossibleIncorrectUsageOfAssignmentOperator',
        'PossibleIncorrectUsageOfRedirectionOperator',
        'ProvideCommentHelp',
        'ReviewUnusedParameter',
        'UseApprovedVerbs',
        'UseBOMForUnicodeEncodedFile',
        'UseCmdletCorrectly',
        'UseCorrectCasing',
        'UseDeclaredVarsMoreThanAssignments',
        'UseProcessBlockForPipelineCommand',
        'UsePSCredentialType',
        'UseShouldProcessForStateChangingFunctions',
        'UseSupportsShouldProcess',
        'PSPlaceOpenBrace',
        'PlaceCloseBrace',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSShouldProcess',
        'PSUseApprovedVerbs',
        'PSUseConsistentIndentation',
        'PSUseConsistentWhitespace')
    Rules = @{
        PSAlignAssignmentStatement = @{
            Enable = $true
            CheckHashtable = $true
        }
        PSAvoidLongLines = @{
            Enable = $true
            MaximumLineLength = 115
        }
        PSProvideCommentHelp = @{
            Enable = $true
            ExportedOnly = $false
            BlockComment = $true
            VSCodeSnippetCorrection = $false
            Placement = "begin"
        }
        PSPlaceOpenBrace = @{
            Enable = $true
            OnSameLine = $true
            NewLineAfter = $true
            IgnoreOneLineBlock = $true
        }
        PSPlaceCloseBrace = @{
            Enable = $true
            NoEmptyLineBefore = $true
            IgnoreOneLineBlock = $true
            NewLineAfter = $true
        }
        PSUseConsistentIndentation = @{
            Enable = $true
            IndentationSize = 4
            PipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
            Kind = 'space'
        }
        PSUseConsistentWhitespace = @{
            Enable = $true
            CheckInnerBrace = $false
            CheckOpenBrace = $true
            CheckOpenParen = $true
            CheckOperator = $true
            CheckPipe = $true
            CheckPipeForRedundantWhitespace = $false
            CheckSeparator = $true
            CheckParameter = $false
            IgnoreAssignmentOperatorInsideHashTable = $true
        }        
    }
}