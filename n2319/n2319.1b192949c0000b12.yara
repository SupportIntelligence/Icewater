
rule n2319_1b192949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.1b192949c0000b12"
     cluster="n2319.1b192949c0000b12"
     cluster_size="136"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack script clicker"
     md5_hashes="['cb702a5c1af64c3878a2c2aa1643fde00fdd24e0','1fb454a16a021e53b7dc5fe588bf874b19b555f6','a2cc7ad628bd1a2a79f2b9f4f8a4ffaa0ef7ca84']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.1b192949c0000b12"

   strings:
      $hex_string = { 6c3d662e737570706f72742e626f784d6f64656c3b76617220693d2f5e283f3a5c7b2e2a5c7d7c5c5b2e2a5c5d29242f2c6a3d2f285b612d7a5d29285b412d5a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
