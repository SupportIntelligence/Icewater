
rule n26d5_6d9f6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.6d9f6a48c0000b12"
     cluster="n26d5.6d9f6a48c0000b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['b0f189f069b968d7da062148b729440fac490f10','b26bafed74c104cd0b4c9f3c3a31522469a915ec','03fc6fc0d2a0d53da2dfe83927edf8468baf2d1f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.6d9f6a48c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
