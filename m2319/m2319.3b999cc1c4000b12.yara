
rule m2319_3b999cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b999cc1c4000b12"
     cluster="m2319.3b999cc1c4000b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clicker faceliker script"
     md5_hashes="['0b1b1a2f88be9a67180e3163717afbee5b326b97','c75449f5051afcbe9edfd04537cbec517ae77b1d','5d0218c4e08dfd701128c2a987567409272ce442']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3b999cc1c4000b12"

   strings:
      $hex_string = { 6e642d696d6167653a75726c28687474703a2f2f312e62702e626c6f6773706f742e636f6d2f2d39464367433353705a30302f55504d69456564473156492f41 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
