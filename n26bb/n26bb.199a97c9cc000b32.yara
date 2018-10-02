
rule n26bb_199a97c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.199a97c9cc000b32"
     cluster="n26bb.199a97c9cc000b32"
     cluster_size="121"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic softonicdownloader downware"
     md5_hashes="['64c37bb37030c86d590d3e72d8e3451105c75d2c','404ba055f3e19a81a848e1eaa36eb4dc46974a9a','c9e140431c343e2159d32e91cf5e96838919006b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.199a97c9cc000b32"

   strings:
      $hex_string = { ead53570a7d1c51f19fe3406eda45c1142ad6c942fdd6e382507828cc452a3fd85b7d274330e0843cfebdbd8f841dc2b3023e7aa1047cbf4872e4dde05ec0f0b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
