
rule k26c0_33b344baca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.33b344baca200b12"
     cluster="k26c0.33b344baca200b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clipspy malicious cometer"
     md5_hashes="['ad9b56317bc563510fd35466c9ad536f076fd1c4','a69557318bec4e07eb75819050e4074758f67eda','f5e22ee0d75958b26317cfaa6261cf50686ba4a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.33b344baca200b12"

   strings:
      $hex_string = { 7a655f636f737400071401a509000015697838365f74756e655f696e64696365730004f8000000076b015a140000115838365f54554e455f5343484544554c45 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
