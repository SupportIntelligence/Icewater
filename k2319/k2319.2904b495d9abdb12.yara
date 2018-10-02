
rule k2319_2904b495d9abdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904b495d9abdb12"
     cluster="k2319.2904b495d9abdb12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['907bd02d18d5e538c8df18301ac02729fea3637c','47769886c0895b26438d90221e66164b21fd6a8b','aaee3f6a17714d0507b8f472f100b392fc7ac181']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904b495d9abdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
