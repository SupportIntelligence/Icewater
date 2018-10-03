
rule o26bb_5292c65edae31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.5292c65edae31b32"
     cluster="o26bb.5292c65edae31b32"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linkury zusy malicious"
     md5_hashes="['9043cc0f28ac6950446e5428e2e052bb129edd7e','bc255e2578562fbfd8747937af3ed66d2b2f2d7f','1070b122eaef68b35869b7ea072a66b3e3863b7f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.5292c65edae31b32"

   strings:
      $hex_string = { cf8945cce8fee9ffff83c4048b55f885d274328a5f1380fb08732a0fb677198d879800000033c985f67e0d39500c741c4183c0143bce7cf30fb6c38994876001 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
