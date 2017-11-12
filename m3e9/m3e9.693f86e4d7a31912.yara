
rule m3e9_693f86e4d7a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f86e4d7a31912"
     cluster="m3e9.693f86e4d7a31912"
     cluster_size="318"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['0265b9689886f6c2b04e4bf737071c2b','0449505a771d2c6e5effb2e54fd32eac','1787c45639e9a35f0a22fd85c9733bf3']"

   strings:
      $hex_string = { 2a73ea3092f4e4d93a0a83f3f66e0e018c61a0eeda4841dfc88a0ddf7ace4ab90211ed5a180882ac4bacb6887e5e323ade3f00164eef2b5ae7410e532faeb3d7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
