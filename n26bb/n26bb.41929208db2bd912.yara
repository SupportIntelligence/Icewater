
rule n26bb_41929208db2bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.41929208db2bd912"
     cluster="n26bb.41929208db2bd912"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious patched sality"
     md5_hashes="['339cdffdef6d9e63ae05ba6fc7de9106b92c7572','8d09bd092a373768946294b1e85a91ae457a14c2','660fa1d1d3c9dd86c2234c94fe989016b2d0ce03']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.41929208db2bd912"

   strings:
      $hex_string = { 5f2dc2d9fd13e188bbbdddb34f520d1c84f27d0370730874cadb0780a60b852ab097638c9cc01d62205b6567b84427400f9331ea009e79a7e524c81befcc43be }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
