
rule j26bf_111cbc49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.111cbc49c0000b32"
     cluster="j26bf.111cbc49c0000b32"
     cluster_size="117"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy starter malicious"
     md5_hashes="['2ef6579f2b2a011f729b4e6d8c7aaecb1e10849c','8032aeceacc6cef6dd5086a85e213a3b61829df1','30bacb16fff595eb2686d05d9562dcbbd3587167']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.111cbc49c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
