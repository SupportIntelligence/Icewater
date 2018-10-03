
rule n2319_699c91e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.699c91e9c8800b12"
     cluster="n2319.699c91e9c8800b12"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script clicker"
     md5_hashes="['403cb15e237a9246e5342c54334b4bdc56eafa80','d03df1a4e5f3c929159b1d27f8f254591f714581','48b9d60fcd1b75152bb44688eddc9f747dd9a93d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.699c91e9c8800b12"

   strings:
      $hex_string = { 7b6261636b67726f756e643a75726c28687474703a2f2f342e62702e626c6f6773706f742e636f6d2f2d557a5153567165333530412f55524a68476148734771 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
