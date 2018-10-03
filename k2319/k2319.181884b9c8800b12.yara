
rule k2319_181884b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181884b9c8800b12"
     cluster="k2319.181884b9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['add30e10e2079490cd64672a27c054402b755df2','e6e6a199f0cdaf22d28aa712be2ff6b2b5e1c66c','ce561dd3ce3dd1e0953a8d7bfce8229eb71c4575']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181884b9c8800b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20755b4f5d3b7d76617220473d28307843413c2835322e2c3078323138293f283131372e2c30786363396532643531293a2834 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
