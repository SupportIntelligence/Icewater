
rule m2319_4b34ca50ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4b34ca50ca210912"
     cluster="m2319.4b34ca50ca210912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['ea4920a8435332215d572f7df6481c9f38fc3c12','388bd0279d2aac0f9aaefcbc14e5caeaa5bd427f','079e6e2da72de0ab112531926670f23f508c5105']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.4b34ca50ca210912"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
