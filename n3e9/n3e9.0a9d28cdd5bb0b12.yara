
rule n3e9_0a9d28cdd5bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0a9d28cdd5bb0b12"
     cluster="n3e9.0a9d28cdd5bb0b12"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy scudy"
     md5_hashes="['02935db213e63ca79635336604c80b72','14cc34be7f0a9f5a12b2b61be140b62e','b708b4daae2d4d88bfad3c340bd7eeb3']"

   strings:
      $hex_string = { 00ce601c03a6806ac4749293ae449aa5d2190d0616899d93ff61aba7ff658884ec5633212763aab0df50c7ceff84715db06948372a5bc7d5ff4fccdeff8b7b6d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
