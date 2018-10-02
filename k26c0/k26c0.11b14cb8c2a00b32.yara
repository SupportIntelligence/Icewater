
rule k26c0_11b14cb8c2a00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.11b14cb8c2a00b32"
     cluster="k26c0.11b14cb8c2a00b32"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clipspy malicious attribute"
     md5_hashes="['d67781f644471404e662c99f512d13047db165b1','9ad74fe378bbe73cdec2bc911241b212c750432f','15f7deaa0c95c2a869de85cc1bd7f3adf50d8b08']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.11b14cb8c2a00b32"

   strings:
      $hex_string = { 7a655f636f737400071401a509000015697838365f74756e655f696e64696365730004f8000000076b015a140000115838365f54554e455f5343484544554c45 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
