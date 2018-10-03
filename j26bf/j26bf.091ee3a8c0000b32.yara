
rule j26bf_091ee3a8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.091ee3a8c0000b32"
     cluster="j26bf.091ee3a8c0000b32"
     cluster_size="84"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="starter generickd malicious"
     md5_hashes="['a78b11b96b54f763664c448d14b85a07ef58319e','4c45405d2f6e37b74c3ebb192f7ea7b5d930cc9a','bc6c475579a30fbf082844aef1254d0d81a40091']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.091ee3a8c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
