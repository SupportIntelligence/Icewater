
rule nfc8_099293b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.099293b9ca800b12"
     cluster="nfc8.099293b9ca800b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker asacub"
     md5_hashes="['f60f41d18e49941c101a1a5f554d5b9ae5972174','7a32df6423879867e1398d9a8e3e4231d0512ea0','db19a8e69aee46e5d77c17ea28b820fdd5eadd39']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.099293b9ca800b12"

   strings:
      $hex_string = { eba731866b09aed5a32830e5256fc1c4bb3874d01b339f7bf945a592f11ab7fb8932f71cbfa2ad14d79d136783d8c5c612c87107e666654c16f49922f3cd8a87 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
