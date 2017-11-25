
rule n3e9_0a9d28cdd5ab4b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0a9d28cdd5ab4b16"
     cluster="n3e9.0a9d28cdd5ab4b16"
     cluster_size="46472"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar mikey rootkit"
     md5_hashes="['0007d07e5692cd576e9b313c71015d90','00087e16736d0605b0e73abeff5bf806','004ab25068e5641ac8b25183a9fcd19a']"

   strings:
      $hex_string = { 00ce601c03a6806ac4749293ae449aa5d2190d0616899d93ff61aba7ff658884ec5633212763aab0df50c7ceff84715db06948372a5bc7d5ff4fccdeff8b7b6d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
