
rule m3ed_3b9ac936d9bf1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac936d9bf1932"
     cluster="m3ed.3b9ac936d9bf1932"
     cluster_size="35"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['3736c125e7795aab3aa85cfe7fdb6db1','5b84319b58f59e47edd5b80e966863da','e234bc325bed9e581b248a7990ab5bcb']"

   strings:
      $hex_string = { a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
