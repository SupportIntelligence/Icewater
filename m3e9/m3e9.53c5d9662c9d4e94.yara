
rule m3e9_53c5d9662c9d4e94
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53c5d9662c9d4e94"
     cluster="m3e9.53c5d9662c9d4e94"
     cluster_size="28"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['04640d0ffeba6c571673a7d3e5fa40c3','20ab837dd9ad10c4a15eda5404173f4a','bd0c70049f2dc2bfe11f19716b37067b']"

   strings:
      $hex_string = { 0904042b71c3c274717153504f0e1363e0f7f7f7fae1cd4323000000037d82858cc6c4c7c6d0d0db402d2d342d2d2b28292d6ec7c7bbbbbb735e4e4e4d0d22bc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
