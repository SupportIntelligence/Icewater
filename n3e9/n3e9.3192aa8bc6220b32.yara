
rule n3e9_3192aa8bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3192aa8bc6220b32"
     cluster="n3e9.3192aa8bc6220b32"
     cluster_size="25"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious cerber heuristic"
     md5_hashes="['045a82c9708f8c7bad9b814e1c17d678','0be4096378f6203dad2c66c29ceeaa5f','9b919828181df13d1b56491b28f09e10']"

   strings:
      $hex_string = { 0ea7e515a2df76ba1c1d0864934b8b47d4eb19ec6af88ac5d8411f7a6fc9edd75d0cfe4d575a102784188320e27d240963db3a80401efb750d5f141217a98659 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
