
rule m231b_0486693496c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.0486693496c30912"
     cluster="m231b.0486693496c30912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos ppsw scrinject"
     md5_hashes="['ac08831f7de6824459f85baa58f76c8ac17cc963','a7c104a1cc19b35e465ce64ea2a776550fc57774','282014b8985afa458cfc4a7e2edffc8a110644cf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.0486693496c30912"

   strings:
      $hex_string = { 426c6f636b537461744368616e676528746869732c27d985d986d988db8c20d8a7d8b5d984db8c272922207372633d222f74656d702f6e756b652f3770782e67 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
