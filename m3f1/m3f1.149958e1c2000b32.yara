
rule m3f1_149958e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f1.149958e1c2000b32"
     cluster="m3f1.149958e1c2000b32"
     cluster_size="6"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="triada androidos appad"
     md5_hashes="['30a0369b95ab2dc3b8a861fe4b4ec3b5','740288a2cbfeb1a489e88c9a9f8016b1','f3c4c51475956e224a24c30519aadd7c']"

   strings:
      $hex_string = { a46c53f5e809e21581ac40cc603008a8be6a9ee097236276fa8e2cbb5ee5395273998aa7c404f31d593e718f5827aeafba832be681659b56dc175d7ef2455c20 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
