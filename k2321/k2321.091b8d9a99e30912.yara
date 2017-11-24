
rule k2321_091b8d9a99e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.091b8d9a99e30912"
     cluster="k2321.091b8d9a99e30912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['00c835ff4dfbaa0afe54b88de976d1f2','04415b2436399e8e22a2437d22c9fe58','e9deabd3b9db2482d942f57f8f5ab9d8']"

   strings:
      $hex_string = { db7f600cf2a6f8ca6fe72bbf5db86a931a41074dbbcfaa34a2ff23423c1d48d90ea0acdf8aefd4b6faf929b5c316dc59c7fb5f273672c28597d0799afe37ba3f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
