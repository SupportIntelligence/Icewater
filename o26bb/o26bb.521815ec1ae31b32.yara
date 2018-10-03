
rule o26bb_521815ec1ae31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.521815ec1ae31b32"
     cluster="o26bb.521815ec1ae31b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linkury zusy malicious"
     md5_hashes="['91449253ae874f9114d6fd6e006661a91e54af73','5580f46396872de55d3f6c60d3457648003c8e6d','855dde71a716537823db74d35a0914c0041f54c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.521815ec1ae31b32"

   strings:
      $hex_string = { cf8945cce8fee9ffff83c4048b55f885d274328a5f1380fb08732a0fb677198d879800000033c985f67e0d39500c741c4183c0143bce7cf30fb6c38994876001 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
