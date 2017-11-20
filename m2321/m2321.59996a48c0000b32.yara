
rule m2321_59996a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.59996a48c0000b32"
     cluster="m2321.59996a48c0000b32"
     cluster_size="88"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy carberp"
     md5_hashes="['017eb9bd498a33b78faa1a73084d6e8a','0296fa2ec01be0853b57317bb1b40a1c','4205ef35de803b61247800aa33f2f9dd']"

   strings:
      $hex_string = { c41bb3b2430bec7cef0ca32622e9385339d19441c18407966218aacb72b804a03acd5c21bf45abf99d3549b470978987f54ebc54f3d5097c56ed8feed091178d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
