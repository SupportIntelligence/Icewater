
rule m26bb_39bc6948c0010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.39bc6948c0010b32"
     cluster="m26bb.39bc6948c0010b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor malicious susp"
     md5_hashes="['802eaabc6afdefb7ff9474d7ee61390ecd5c335d','163285b0ee0cb5302f151668643b3b0b5739a131','33e1d6a54064e2bfa14b1b030564b0b84fe19e55']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.39bc6948c0010b32"

   strings:
      $hex_string = { 11e1ad3c44a4e0194c190ca040e98056490563b18332f45265faf3e66f94ff7ec8f069e4c022015c5f4dc2ceb7cd8a7cd1258541a26b9a732b72f58d8be2bcbf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
