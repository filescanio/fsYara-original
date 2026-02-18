rule psLoader
{
    meta:
        author = "OPSWAT"
        score = 80

    strings:
        // comment
        $comment_1  = "MATRIX DECRYPTION SYSTEM - AES Layered Defense Pattern"
        $comment_2  = "Create AES decryptor"
        $comment_3  = "Rotate execution methods with more randomness"
        $comment_4  = "Check for common sandbox usernames"
        $comment_5  = "Validate decrypted content"
        $comment_6  = "Random delay with jitter to avoid pattern recognition"
        $comment_7  = "Add random garbage operations to obfuscate"
        $comment_8  = "Advanced cleanup - overwrite sensitive variables"
        $comment_9  = "Execute AES decryption sequence"
        $comment_10 = "Force garbage collection"
        $comment_11 = "Execute with enhanced obfuscation"
        // Layer
        $layer_1 = "LAYER 1: Data Reconstruction"
        $layer_2 = "LAYER 2: Core Transformation Functions"
        $layer_3 = "LAYER 3: Execution Engine with Anti-Debugging"
        $layer_4 = "LAYER 4: Advanced Validation Functions"
        $layer_5 = "LAYER 5: Main Orchestration Sequence"
        $layer_6 = "LAYER 6: Execution Framework"
        // Phase
        $phase_1 = "Phase 0: Environment Validation"
        $phase_2 = "Phase 1: Material Reconstruction"
        $phase_3 = "Phase 2: AES Decryption"
        $phase_4 = "Phase 3: Payload Reconstruction with validation"
        // var
        $var_1  = "CipherMatrix"
        $var_2  = "KeyCipher"
        $var_3  = "IVCipher"
        $var_4  = "byteStream"
        $var_5  = "scriptBlock"
        $var_6  = "ScriptPayload"
        $var_7  = "selectedVector"
        $var_8  = "rotationSeed"
        $var_9  = "suspiciousProcesses"
        $var_10 = "runningProcesses"
        $var_11 = "sandboxUsers"
        $var_12 = "currentUser"
        // func
        $func_1 = "Initiate-AESDecryptionSequence"
        $func_2 = "Invoke-StealthExecution"
        // msg
        $msg_1 = "Suspicious environment detected"
        $msg_2 = "Reconstructing payload..."
        $msg_3 = "Decrypted content appears invalid"
        $msg_4 = "No payload to execute"
        // failure types
        $failure_1 = "VALIDATION_FAILURE"
        $failure_2 = "MATRIX_FAILURE_AES"
        $failure_3 = "PAYLOAD_FAILURE"

    condition:
        4 of ($comment*) or
        3 of ($layer*) or
        3 of ($phase*) or
        7 of ($var*) or
        1 of ($func*) or
        2 of ($msg*) or
        all of ($failure*)
}
