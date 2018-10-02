
rule k2319_105b0299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.105b0299c2200b12"
     cluster="k2319.105b0299c2200b12"
     cluster_size="90"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c376de740d3a84c15aab0dd2421f9283e6eb6b1c','82db1e7d85f1013a895db84dff7fba6a27407bd1','999adf7d6407aa3133e3c2e354069a741d791b38']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.105b0299c2200b12"

   strings:
      $hex_string = { 495b585d213d3d756e646566696e6564297b72657475726e20495b585d3b7d76617220453d282831302e343745322c3078313541293e3d35362e3f2837392e33 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
