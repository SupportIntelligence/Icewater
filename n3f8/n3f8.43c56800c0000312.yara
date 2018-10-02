
rule n3f8_43c56800c0000312
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.43c56800c0000312"
     cluster="n3f8.43c56800c0000312"
     cluster_size="68"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zdtad androidos addisplay"
     md5_hashes="['eddd12dec94967603a6126c72f5f0d766624dd58','ee712e447682016b85fce694e87152cfce5cf719','39e19524e2b18d9d87c298124d1160e20a7ff9ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.43c56800c0000312"

   strings:
      $hex_string = { bd93e5898de794a8e688b770757368e997b4e99a94e697b6e997b4e4b8ba3d0033426f6f7452656365697665722e73657450757368416c61726d2853505f4b45 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
