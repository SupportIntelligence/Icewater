
rule k2319_2904b494d9abdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904b494d9abdb12"
     cluster="k2319.2904b494d9abdb12"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['5291e961e309e318c108b928cf02353a57661f6b','fa33826e20e193a48fe9a5e55bbb82b97b842b25','f7114c1fa93c6b0d4b639ed5f420e1e37d3f266d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904b494d9abdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
