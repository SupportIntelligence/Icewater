
rule m3e9_059856c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.059856c9cc000b32"
     cluster="m3e9.059856c9cc000b32"
     cluster_size="617"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['0124bd00cb117bf548fa0d9743fcd02d','01f253efc0fb6e25528b5cd8cb294330','1108f865e4750d55b735ba467e4d9e3c']"

   strings:
      $hex_string = { 4dfc8b0989088a0b8848048345fc0446433bf77cb733dba160e700018d34d8833eff754d85dbc646048175056af658eb0a8bc348f7d81bc083c0f550ff15d010 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
