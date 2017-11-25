
rule n3e9_0b131bc9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b131bc9c8000b16"
     cluster="n3e9.0b131bc9c8000b16"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler adwaredealply"
     md5_hashes="['29d8b61148ce26b6dd5c6d993b51b114','564b46b412e91cf0acd9836802ba4201','d2e11a60f6a0e84c5dac68b8c3b3ad09']"

   strings:
      $hex_string = { f509466f6e742e4e616d65060d4d532053616e732053657269660a466f6e742e5374796c650b000d506978656c73506572496e636802600a5465787448656967 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
