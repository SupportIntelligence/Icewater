
rule n26d5_2d956a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d956a48c0000b12"
     cluster="n26d5.2d956a48c0000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious aacb"
     md5_hashes="['5ba8606379b2619ad00fffbb34ed453097041524','179654d40cd03bd74e1d786e9f2101d57b8d5230','4e5609f75f78bb3316d3ac41bb7e52c6f7608aed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d956a48c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
