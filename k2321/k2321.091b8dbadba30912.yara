
rule k2321_091b8dbadba30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.091b8dbadba30912"
     cluster="k2321.091b8dbadba30912"
     cluster_size="4"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['2053ea00d6d939a7247d54e8affd92fd','6d04126836de19f0f9de207cb9bd6c4d','96bc0c8cdb516fa9ff9f9dc896e246f1']"

   strings:
      $hex_string = { db7f600cf2a6f8ca6fe72bbf5db86a931a41074dbbcfaa34a2ff23423c1d48d90ea0acdf8aefd4b6faf929b5c316dc59c7fb5f273672c28597d0799afe37ba3f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
