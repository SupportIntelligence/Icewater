
rule o2319_3b1d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.3b1d6a48c0000b12"
     cluster="o2319.3b1d6a48c0000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive miner"
     md5_hashes="['a6664b84f62c6201f31b1a268741d9c954f57abd','b643a4af6351ee2d84ab8906245ff574bfebe308','bd14da5030551ae560b99b119dcbf136003f7c3f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.3b1d6a48c0000b12"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
