
rule n2319_13995ec1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13995ec1c8000b32"
     cluster="n2319.13995ec1c8000b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker clickjack"
     md5_hashes="['ab9ed18b9a964a63c03e923f59da9cd69841ba38','ddabe9eff583ba84dc02d57bbd3b4f7f80517ed6','e9510499c9dac5e9992f84719a8f377340893e10']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13995ec1c8000b32"

   strings:
      $hex_string = { 6c3d662e737570706f72742e626f784d6f64656c3b76617220693d2f5e283f3a5c7b2e2a5c7d7c5c5b2e2a5c5d29242f2c6a3d2f285b612d7a5d29285b412d5a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
