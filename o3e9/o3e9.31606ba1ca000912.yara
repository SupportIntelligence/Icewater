
rule o3e9_31606ba1ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.31606ba1ca000912"
     cluster="o3e9.31606ba1ca000912"
     cluster_size="2590"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor malicious unwanted"
     md5_hashes="['00461fb44249659bd46d2640e776b159','006f8f33d03b86b9a20f50de55b927b5','02179f1b320f35c0601cf859cef5bf66']"

   strings:
      $hex_string = { 6fc47d7152a71b207b1f4847d4b9e7447cbe6ea4ebf4c52137e93e651521e4d4b8c21863c629a8b5a4bb880abab8dae3cb9843bc8e53c4579b7b832c224eb97f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
