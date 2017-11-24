
rule m24c1_14995cc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c1.14995cc1cc000b32"
     cluster="m24c1.14995cc1cc000b32"
     cluster_size="6"
     filetype = "Dalvik dex file version 035 (Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="triada androidos appad"
     md5_hashes="['04c4b8cd9ebb549d22375a965d19cf6e','24ceceff1de4f7756c7ea0f42d18d999','fd1d2cf59be1473cb2f895ae0bcb9887']"

   strings:
      $hex_string = { a46c53f5e809e21581ac40cc603008a8be6a9ee097236276fa8e2cbb5ee5395273998aa7c404f31d593e718f5827aeafba832be681659b56dc175d7ef2455c20 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
