
rule j2319_5c6e383520564cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5c6e383520564cba"
     cluster="j2319.5c6e383520564cba"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="webshell html script"
     md5_hashes="['7ab4a91e8c16ad469d39fbc1321130d3044ed5e6','b8e2f1a94854d877ffa19c589ff7edb8144eceef','802772f251dfe35759b00438537a6c292eec34f9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.5c6e383520564cba"

   strings:
      $hex_string = { 742e636f6d2e706b202d2057534f20322e363c2f7469746c653e0d0a3c7374796c653e0d0a626f64797b6261636b67726f756e642d636f6c6f723a233434343b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
