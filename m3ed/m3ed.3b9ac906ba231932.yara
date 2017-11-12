
rule m3ed_3b9ac906ba231932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac906ba231932"
     cluster="m3ed.3b9ac906ba231932"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['0329cc4ded96b1ca9f18bfa28513e2e1','515ee760e9e3a6d01e5b0ed6cf8cb210','c85009865f8bcb13cb8b1de05b909f83']"

   strings:
      $hex_string = { a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
