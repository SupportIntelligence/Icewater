
rule n3e9_4b9eea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b9eea48c0000b12"
     cluster="n3e9.4b9eea48c0000b12"
     cluster_size="885"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['02194e35ee147f07b360aa046bcff3b6','029f195243b940409af3f07f415f24b5','12b08cfb7041073184eced311cb827b3']"

   strings:
      $hex_string = { 917184498626aad31a0ea48093771f50ebd9e1a7fe2a5c17b8adfb67ac56369587af358f90864538bc972db39f362629f3b856967b163046b488734c4d24725c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
