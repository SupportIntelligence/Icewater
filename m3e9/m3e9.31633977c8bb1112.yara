
rule m3e9_31633977c8bb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31633977c8bb1112"
     cluster="m3e9.31633977c8bb1112"
     cluster_size="186"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['01d120c1a6773ac88a1ef589b2f7454e','03cad49d49e05c9dd3011f0d4a10265f','449532295bd329534c2f066ab99ff348']"

   strings:
      $hex_string = { ac6b268c9615ccde1abde327c44b634c500fb35af42057ef3bf7e1b3483dce426439e4afa8f423d1102f5bae5304b95349d59eed0ec8cdcfba668170badabfbd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
