
rule m3e9_2fe294c348000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2fe294c348000132"
     cluster="m3e9.2fe294c348000132"
     cluster_size="80"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downware unwanted downloadshield"
     md5_hashes="['0d0050987487dac24b1a0cc273b249d2','110fbd88fcfe35a6cf7454d5b9500426','41b6df931e41b6fecf1901903ae0442c']"

   strings:
      $hex_string = { 886eba180cdbec4cf9cdd65b09cf0486e3d0c3f37b4612f8033e8b92136a2aaad766f1a1c1364398bbe000ce33a4962f0737ea1bb2e608fd9e2cb3e8a5015f63 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
