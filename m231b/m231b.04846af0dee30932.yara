
rule m231b_04846af0dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.04846af0dee30932"
     cluster="m231b.04846af0dee30932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos ppsw scrinject"
     md5_hashes="['7f74fcde3b8959679e51f5886785991856fb5d48','09e28dd4d1009cad15df8d8d9976bce1fbb5ed5d','84ba0c23abaa325e0f8b6a7bfb42562c648c25a5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.04846af0dee30932"

   strings:
      $hex_string = { 426c6f636b537461744368616e676528746869732c27d985d986d988db8c20d8a7d8b5d984db8c272922207372633d222f74656d702f6e756b652f3770782e67 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
