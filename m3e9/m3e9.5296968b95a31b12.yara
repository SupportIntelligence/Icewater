
rule m3e9_5296968b95a31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5296968b95a31b12"
     cluster="m3e9.5296968b95a31b12"
     cluster_size="27"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt vobfus kazy"
     md5_hashes="['0f083fb9aaccc5ffd9b46cf27e77286d','105b1fb182c8ad25de5757972953f639','c2a8fce704c24c44e72574d26bcd290e']"

   strings:
      $hex_string = { 4368b863ef1007fa5e7b55a1194e7ab0a9fd20de7fd37513abe63ce2d8598e6dcbb1a51533c5418085c9f3498cca960954009c454108dcbf178ddd5f2c16ae89 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
