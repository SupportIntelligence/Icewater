
rule n3e9_0a9d388dc7ab4b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0a9d388dc7ab4b16"
     cluster="n3e9.0a9d388dc7ab4b16"
     cluster_size="26522"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar graftor rootkit"
     md5_hashes="['00026c80e5ebed1bae5da42783c7caac','00150e8763cf164605cc66b8a586d257','00d7d0a2f9f458c262c0348db16e992d']"

   strings:
      $hex_string = { 00ce601c03a6806ac4749293ae449aa5d2190d0616899d93ff61aba7ff658884ec5633212763aab0df50c7ceff84715db06948372a5bc7d5ff4fccdeff8b7b6d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
