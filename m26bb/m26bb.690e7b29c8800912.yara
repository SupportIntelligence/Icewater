
rule m26bb_690e7b29c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.690e7b29c8800912"
     cluster="m26bb.690e7b29c8800912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="amonetize faet fefcee"
     md5_hashes="['6f04d50e3c0d9d3499086a9bf7e437e042166e60','725c43618a702d48af6c1c212973a44120fa9348','dab3d305e98935e2d0e4e5a04162ed448a3847f5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.690e7b29c8800912"

   strings:
      $hex_string = { 0447ff45fc3bfb7c8e33db8bf3c1e606033540a441008b0683f8ff740b83f8fe7406804e0480eb71c646048185db75056af658eb0a8d43fff7d81bc083c0f550 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
