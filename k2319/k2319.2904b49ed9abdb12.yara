
rule k2319_2904b49ed9abdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904b49ed9abdb12"
     cluster="k2319.2904b49ed9abdb12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['a1a78665bef7ca06f1f0e6cd18bc3962f1b270cb','d37094f19ce441e449e65f6f90bff933c650d904','2de0bc4f6dc70fd59919dc61b38f916f4914fe6b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904b49ed9abdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
