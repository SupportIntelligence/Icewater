
rule m3e9_29d4e449c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29d4e449c0000b32"
     cluster="m3e9.29d4e449c0000b32"
     cluster_size="92"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['01fd5e99d53eabe54767880a7152db99','0bdb7c981074e5f6dc945d445ae09aec','5e8b4bc9d506d4c8a6e1640976b3940d']"

   strings:
      $hex_string = { 5e65af057886827e3e484a4ea64330575b63af0b7d898b8a4d4b496a555138585c64af29888c8d926d313c3a53503b595d1705768f8e90948456473f0234376c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
