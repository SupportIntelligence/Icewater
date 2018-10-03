
rule n26bb_311e3ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.311e3ec1cc000b12"
     cluster="n26bb.311e3ec1cc000b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro malicious ccnc"
     md5_hashes="['92b998e5f5c8984daa2fdf4b3252282f57467a27','1ee5c747fa874a49c4afa470017768e2952634bc','cf89d85e7b9f6b75af9d64b2581ccf791d794556']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.311e3ec1cc000b12"

   strings:
      $hex_string = { 56578b7d0c8b45088327008d5002668b0840406685c975f62bc2d1f88bf08d46016bc006688c19001033c96a02d1e85af7e20f90c1f7d90bc851e8d8f8ffff59 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
