
rule n2319_09b913a9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.09b913a9ca000912"
     cluster="n2319.09b913a9ca000912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['4d0344be4cd390c066c566539048ff187c6cb733','4eab5c988e81a844d2c4a84bb6cb8fa544d5bfd5','0260f30c64595e4d4f35dbf3bf2945b13df62f51']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.09b913a9ca000912"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
