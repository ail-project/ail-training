rule disney_plus : credential_leak 
{
    meta:                                        
        description = "Finding list of credentials for Disney Plus"
        leak = 1
    strings: 
        $a = "gmail.com:"
        $b = "DISNEY_PLUS"
        $c = "Disney Plus"
    condition:
        $a and ($b or $c) 
}
