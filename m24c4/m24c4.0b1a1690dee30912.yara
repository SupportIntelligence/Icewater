
rule m24c4_0b1a1690dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c4.0b1a1690dee30912"
     cluster="m24c4.0b1a1690dee30912"
     cluster_size="5"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery pemalform riskware"
     md5_hashes="['24c6143525b14501c5be25f9720c9ed8','8533d6bb612aa3b714968b7306c6e647','af6ad3a2c57d5a85a2d40332ec6f235f']"

   strings:
      $hex_string = { af4884cf79a840f544e88b5b017d2590b57ba9e76bffcc0583be361c10d83d9fb18639ec9ea7e1e273defe307c87bbdd37bc58ace5446d2fef9776d9c51e5967 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
