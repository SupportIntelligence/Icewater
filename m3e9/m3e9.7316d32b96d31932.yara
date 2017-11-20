
rule m3e9_7316d32b96d31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7316d32b96d31932"
     cluster="m3e9.7316d32b96d31932"
     cluster_size="64"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="conjar vobfus diple"
     md5_hashes="['1e4e77b9bf7802452f1de225b224e469','4d8b2b2f7020750011cd14a25b83fdd9','ace4ed9bf0d83cc745e95bdcfff1a3d8']"

   strings:
      $hex_string = { dad6cacbbfb692958c17193cb9d5daf6f6f3d8c84b25000000252a32323f6dcaf2f2f6f9d74931303f49b5bcd7f0f2f2d8d5c1c0beb87a9491791a1f61d4f6da }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
