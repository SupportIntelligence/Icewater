
rule n2319_4b945ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4b945ec1c4000b12"
     cluster="n2319.4b945ec1c4000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker script"
     md5_hashes="['dd32d442ace97b601eaf0200ed8a0dbcc07b2c20','a457d52af9cf6a016d7a345a7491942a8d28318c','d7fb91d41038e06be1378c3150d2c80fdb03ce34']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4b945ec1c4000b12"

   strings:
      $hex_string = { 297d3b766172206b623d6465636f64655552492822253733637269707422292c6c623d2f5e5b2d2b5f302d395c2f412d5a612d7a5d2b3d7b302c327d242f2c6d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
