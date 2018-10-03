
rule m26d7_61bb6b72d9fb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.61bb6b72d9fb0912"
     cluster="m26d7.61bb6b72d9fb0912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['14d794a67118bfeb7880c258e115ba247618d35a','1bb894f52f6a90e5786f3b02ced0b74c7d79d987','b621498f47c7658b473b7fcbd0cc07c274edf2b5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.61bb6b72d9fb0912"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
