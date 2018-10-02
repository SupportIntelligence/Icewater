
rule k2319_691ab199c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691ab199c2200b32"
     cluster="k2319.691ab199c2200b32"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['98d28a1bcf42918534ead10791aea9aeb9e6aa65','ee2c85b4200edbf787d3f9853509cccf6da82aba','bbabfff077007fa54af288f6066ac6eafafcb30c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691ab199c2200b32"

   strings:
      $hex_string = { 31332e313445322c30783735292929627265616b7d3b766172204e375936783d7b277a3067273a2866756e6374696f6e28297b766172204f3d66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
