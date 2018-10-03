
rule o26bb_13893929c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.13893929c0000916"
     cluster="o26bb.13893929c0000916"
     cluster_size="526"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwanted"
     md5_hashes="['3d15536e9d98545c9377801e748b807069a46cd1','a0103a8260683b185c7879a01c2fe71aee169a31','7b37dad261c4913c942f554c7e1b519aa38f1c51']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.13893929c0000916"

   strings:
      $hex_string = { 1b104996515a5d4e32164d7f22dc856b82ec1a751572b0d45e94e68055b23c5bc186d1c626c2cf27adea34180cb6442b1c84f0d7bca3178b25130881c99ccc69 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
