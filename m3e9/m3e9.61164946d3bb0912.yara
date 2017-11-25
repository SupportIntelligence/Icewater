
rule m3e9_61164946d3bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61164946d3bb0912"
     cluster="m3e9.61164946d3bb0912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['4a4edf6ad4574d191d5e556954fab5a3','bdf3bca51b28aee503ffa25a3093cde6','d2b308a5b2ddb8f24d3fc4d7bae5ca37']"

   strings:
      $hex_string = { 1c8aa0dfe7b3079303423392d749dc7d0104a68d84f15964840bf7e3c6f85f8f3e3a9f60bd885ddf97e2a29bd5e59ade945e4898773f8b844fb0b23780f28321 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
