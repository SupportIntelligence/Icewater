
rule o3e9_51b63392d43b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.51b63392d43b0932"
     cluster="o3e9.51b63392d43b0932"
     cluster_size="3840"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor atraps flystudio"
     md5_hashes="['0067876f836f37f3f926a3e9fae33333','0076ddad52ddf8de29ff03bb2b9f6c4f','03b2e829880d226b2d16f3c38a4b27a1']"

   strings:
      $hex_string = { 505ebdcc33eca156ad3f115caaab653bd199e83c77d45d0a9c9466551b9f39ea1d31f1ed28cbc6fcceff00d37938f52b19d662f98ad98bf89db32415b7148f68 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
