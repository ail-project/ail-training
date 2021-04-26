rule pay_drugs_in_monero 
{
    meta:
        author = "@gallypette"
        info = "Good medicines only"

    strings:
	$var1 = "LSD" wide ascii nocase
	$var2 = "MDMA" wide ascii nocase
	$var3 = "cannabis" wide ascii nocase
	$var4 = "weed" wide ascii nocase
	$var5 = "ketamine" wide ascii nocase
	$var6 = "cocaine" wide ascii nocase
	$var7 = "amphetamine" wide ascii nocase

	$pay1 = "monero" wide ascii nocase
	$pay2 = "etherum" wide ascii nocase

    condition:
	2 of ($var*) and 1 of ($pay*)
}
