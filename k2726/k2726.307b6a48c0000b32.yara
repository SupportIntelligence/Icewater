
rule k2726_307b6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2726.307b6a48c0000b32"
     cluster="k2726.307b6a48c0000b32"
     cluster_size="118"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="patched malicious susp"
     md5_hashes="['2c9681464a708e28b82facf450b422dfdff707bb','2045627849ede3889e9eb98aff41d63994bedb79','cadf96aa0e2bb052a96360b609e69687a037edc2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2726.307b6a48c0000b32"

   strings:
      $hex_string = { 5e5dc20800cccccccccc8bff558bec515153568bf033db56895dfc895df8ff153c10ba773bc374498d0c468d41fe6683383e752866891848483bc60f84300100 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
