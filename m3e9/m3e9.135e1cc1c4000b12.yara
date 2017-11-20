
rule m3e9_135e1cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.135e1cc1c4000b12"
     cluster="m3e9.135e1cc1c4000b12"
     cluster_size="19"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['359e0a581b17997653d94b6e4d5aefbc','b55ba3e1a91f0e3386b9fb5e4781228a','e61c83ffe231a860c7aa9dd7237cec07']"

   strings:
      $hex_string = { 150a0e13151e50515c5c5d688b8e8d8a7c69969795b5c6a0bb9fc3ccd9f8fffffffffaf9f1ad000000f2ffff65151f1e0f10121e22575c5d7a7d80a6abc8c8bb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
