
rule j26bf_091ea4c8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.091ea4c8c0000b32"
     cluster="j26bf.091ea4c8c0000b32"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="starter malicious fnjo"
     md5_hashes="['de50f52014a973d21a9008be8aea0313201deb39','30ab3bffbaabe4af269c8c49cfb9221327fe3b0f','32a33f6426fb53c690148c7f21f39f9ea4fc9583']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.091ea4c8c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
