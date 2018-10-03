
rule m2319_24158498d9a39912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.24158498d9a39912"
     cluster="m2319.24158498d9a39912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos hidelink script"
     md5_hashes="['c358f32a2f00fb904155c08856c9df9a71ae48d7','6056fab8594139913c7ed0411cde2bb05912f320','8ed432b5a51f71c0230f49e315d032ade9d812dc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.24158498d9a39912"

   strings:
      $hex_string = { 73776f72645f6868272e73706c697428277c27292c302c7b7d29290a76617220746578745f313d22d984d8b7d981d8a720d8b5d8a8d8b120daa9d986db8cd8af }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
