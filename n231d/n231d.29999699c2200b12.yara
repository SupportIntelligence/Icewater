
rule n231d_29999699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.29999699c2200b12"
     cluster="n231d.29999699c2200b12"
     cluster_size="55"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware smssend androidos"
     md5_hashes="['53ccc9a23014cc6f227d8f7aad099971f3cce12a','5e50be5e6a1531ea8c14f6990a63ab65362bf723','3e62ddc3681ed15db303fb80010ad2f8ca8240ea']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.29999699c2200b12"

   strings:
      $hex_string = { fe779967437a68a5164826d4669b782e842a1cd518516afff032756457c6c5c0e9e69a1f698cf8ebefe8859fa3bdf47fd7da4d404f3370c84409fae01a063ae7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
