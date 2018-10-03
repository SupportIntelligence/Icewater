
rule o26bb_23c38399c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.23c38399c8000b16"
     cluster="o26bb.23c38399c8000b16"
     cluster_size="1896"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwanted"
     md5_hashes="['1bbf799bf98eedf7043b836d57dc58d28e4dd29b','4ef1dd38a536b61baac531592e99bc2f34598555','2146757633cab622c9382115d91770670c40bd58']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.23c38399c8000b16"

   strings:
      $hex_string = { 1b104996515a5d4e32164d7f22dc856b82ec1a751572b0d45e94e68055b23c5bc186d1c626c2cf27adea34180cb6442b1c84f0d7bca3178b25130881c99ccc69 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
