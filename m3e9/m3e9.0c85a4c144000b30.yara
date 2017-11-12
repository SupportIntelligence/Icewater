
rule m3e9_0c85a4c144000b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0c85a4c144000b30"
     cluster="m3e9.0c85a4c144000b30"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte installer optimum"
     md5_hashes="['4f55eee32a90e0f60d0fab327588b1c0','74e6d5f03805306252275afcf414af09','e3a2785653a781d4eed7a4c1cf2a1f2d']"

   strings:
      $hex_string = { 710307f6f3394d8b36211b01dfd9da5e2beb0e97801e441c5088f5c612334aa84da58d2f940c7bc6bf9a2cc332cdbd8c2726f0e13003500682bcf43bb3837506 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
