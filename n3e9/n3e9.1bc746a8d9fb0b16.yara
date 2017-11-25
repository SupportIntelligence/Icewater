
rule n3e9_1bc746a8d9fb0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc746a8d9fb0b16"
     cluster="n3e9.1bc746a8d9fb0b16"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious susp"
     md5_hashes="['40c072d4e2324c4f288d631e68a7e1ce','4520453b333682060ea024c1c19d0970','4b5f3c53300bb636e7e924627a37e336']"

   strings:
      $hex_string = { 000b00590065007300200074006f002000260041006c006c00040042006b005300700003005400610062000300450073006300050045006e0074006500720005 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
