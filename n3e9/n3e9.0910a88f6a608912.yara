
rule n3e9_0910a88f6a608912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0910a88f6a608912"
     cluster="n3e9.0910a88f6a608912"
     cluster_size="245"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softpulse bundler riskware"
     md5_hashes="['00a21ce6582288ec22bcfbaa7ed24bd3','032e208dea19d12c5efc131427ab6f53','1786bcb2d1f3a3c55df9f85a6da8d948']"

   strings:
      $hex_string = { d9b41b398df2c68073d45feb55b09bdff02a3aaa834d0644a5ac536a12f7cf8ad1bd74954fc1724a3df6b35ee228a8867999142e2175c292b1e5a4a01ea3ecb8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
