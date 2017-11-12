
rule m3e9_276fa441c0001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.276fa441c0001112"
     cluster="m3e9.276fa441c0001112"
     cluster_size="1870"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik trojandownloader"
     md5_hashes="['0001c963ab6546c5b4257d14f42c9ad7','001ac03d8d2737d77617b1dc8b71c12e','0361a3fe5ce9f7bd4d28feb9c3a05fc3']"

   strings:
      $hex_string = { ff558bec83ec208b450856576a0859be749440008d7de0f3a58945f88b450c5f8945fc5e85c0740cf600087407c745f4004099018d45f450ff75f0ff75e4ff75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
