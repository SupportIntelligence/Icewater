
rule m26d7_69bb5970d8fb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.69bb5970d8fb0932"
     cluster="m26d7.69bb5970d8fb0932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['8ffb979251a491e7ca541712c5819fb27d67005d','8970922e3a4fab475b0f2964f4badb4bfe98a9a8','e9ec3e6365bf915835c9bd40d4823de62f13214c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.69bb5970d8fb0932"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
