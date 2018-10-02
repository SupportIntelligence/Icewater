
rule o26bb_3b9d5259bb230b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.3b9d5259bb230b12"
     cluster="o26bb.3b9d5259bb230b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kuaizip kuzitui malicious"
     md5_hashes="['273c2328e69254b39c235c3f519bb3a2a4dd669f','6626e2378403b3a2d5bbd7471d3804745136e904','388a746a91abc6fcb4c5901c69f0700fa11cfbb4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.3b9d5259bb230b12"

   strings:
      $hex_string = { cbe87ea3feff83c408eb0f8b4c243085c97407894810c64001fe85f67432807f1308732c33c08d8f94000000384719761139710c74560fb657194083c1143bc2 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
