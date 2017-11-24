
rule m3e9_051a52d2c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.051a52d2c4000b32"
     cluster="m3e9.051a52d2c4000b32"
     cluster_size="168"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="aqnv rotinom folstart"
     md5_hashes="['007b000794493c307d3aab150f36c215','038535f7dba51fb090180beb0ee3a2a7','1ecff810b8b0d8773b7296b0d2b098cf']"

   strings:
      $hex_string = { 1bebcb3f3afcc224f3d6905db886238eb7333e1b6ece2034d3458ad960cf61c6b27cea8b62b3fd603155f5070a432cbd02f4637e963def2fa83cb4469ae1ed79 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
