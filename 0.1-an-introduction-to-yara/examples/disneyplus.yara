rule disney_plus : credential_leak 
{
    meta:                                        
        description = "Finding list of credentials for Disney Plus"
        leak = 1
    strings: 
        $a = "gmail.com:"
        $d = "hotmail.com:"
        $e = ".com:"
        $f = ".de:"
        $b = "DISNEY_PLUS"
        $c = "Disney Plus"
    condition:
        ($a or $d or $e or $f) and ($b or $c) 
}
