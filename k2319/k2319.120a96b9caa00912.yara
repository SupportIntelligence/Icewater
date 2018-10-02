
rule k2319_120a96b9caa00912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.120a96b9caa00912"
     cluster="k2319.120a96b9caa00912"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['68ea480e3af494300781cdcde060f97d091039ec','5ff3b36f773db051e43a752a44c2550ab14ca865','d7bf2a310fb0ecfbcdd69aa93a7bc1b4d651dc9c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.120a96b9caa00912"

   strings:
      $hex_string = { 3f28312e30333645332c313139293a2839362e3545312c30783141292929627265616b7d3b76617220793559376c3d7b2751396c273a66756e6374696f6e286a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
