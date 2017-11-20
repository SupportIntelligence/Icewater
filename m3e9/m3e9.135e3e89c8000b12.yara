
rule m3e9_135e3e89c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.135e3e89c8000b12"
     cluster="m3e9.135e3e89c8000b12"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['22b84cedc604763e2a8cf5e8388f89fd','804a843cb9394354f1a6b3deade3aff0','ed2508779374072b6cd2441c41d53498']"

   strings:
      $hex_string = { 77305470afb0b3b1a25f5fa2bbc0d5d5f11180d69726ddd9b9812900000000000000000000000089f2f9f9f1fea2727350516267757476705d5b6c9fb2bcbdd8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
