
rule n2319_11b9684ba6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.11b9684ba6220912"
     cluster="n2319.11b9684ba6220912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos miner script"
     md5_hashes="['04a7b8a0b69247d717c6fe3108371531017b219b','1d53ead4e170827e405ff3841a5a1f33884026b0','a696a6d484516614e87943d09c95651a61a61ca5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.11b9684ba6220912"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
