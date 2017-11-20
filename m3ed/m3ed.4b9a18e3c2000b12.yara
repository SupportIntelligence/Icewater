
rule m3ed_4b9a18e3c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4b9a18e3c2000b12"
     cluster="m3ed.4b9a18e3c2000b12"
     cluster_size="4"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sality crypt salpack"
     md5_hashes="['ac402211e6903e817a50952448693301','adb461b243cbcdb0a10292f2842b41d3','c92e28a16a7e068b81fbe932925b2990']"

   strings:
      $hex_string = { 00e001004000000085379937b437ce37db37ed37fa370e3814381a382738353840384d3873389738a438b138b938bf38cc38eb380f391c392939ae39be390000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
