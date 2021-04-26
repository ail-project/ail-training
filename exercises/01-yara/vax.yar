rule find_me_a_vaccine
{
    meta:
        author = "@gallypette"
        info = "Good vaccines only"

    strings:
	$var = "pfizer" wide ascii nocase
	$var1 = "biontech" wide ascii nocase

	$var2 = "moderna" wide ascii nocase
	$var3 = "sputnik v" wide ascii nocase
	$var4 = "astrazeneca" wide ascii nocase

	$vac = "vaccine" wide ascii nocase
	$cov = "covid" wide ascii nocase


    condition:
        (($var and $var1) or $var2 or $var3 or $var4) or ($vac and $cov)
}
