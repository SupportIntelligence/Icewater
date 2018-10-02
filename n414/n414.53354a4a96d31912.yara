
rule n414_53354a4a96d31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n414.53354a4a96d31912"
     cluster="n414.53354a4a96d31912"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dangerousobject kryptik malicious"
     md5_hashes="['17d1c3a6a0ef2496136f36b3ed4c6454fb2e9d15','c89961cfe005e0539c751fe90509c9f5e8c6b3a6','dd8d9eafc2653cffb1d5823e1a6c5aee174709dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n414.53354a4a96d31912"

   strings:
      $hex_string = { 8d902931778106890f2bdf1412270d711f5121de5b1c38b2a7fe6119bfdeaa3b0c982822363e478cf744cc74f10e8470d6c59e83d1ce579a0509919482e6bba1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
