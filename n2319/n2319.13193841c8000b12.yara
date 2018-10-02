
rule n2319_13193841c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13193841c8000b12"
     cluster="n2319.13193841c8000b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack script clicker"
     md5_hashes="['dc415305e1daee9e38900ec06b223ec0866df72b','2340e917e849c9d5f013cc66c7f66cb88792182b','d57a895bcc632f412bd3998125a16ae10b38f914']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13193841c8000b12"

   strings:
      $hex_string = { 6c3d662e737570706f72742e626f784d6f64656c3b76617220693d2f5e283f3a5c7b2e2a5c7d7c5c5b2e2a5c5d29242f2c6a3d2f285b612d7a5d29285b412d5a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
