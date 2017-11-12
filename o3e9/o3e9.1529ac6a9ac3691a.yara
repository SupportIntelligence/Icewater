
rule o3e9_1529ac6a9ac3691a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1529ac6a9ac3691a"
     cluster="o3e9.1529ac6a9ac3691a"
     cluster_size="743"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster bundler installmonstr"
     md5_hashes="['00598413dd37c914517788f20527accc','00e2ece8e8b097a6ba2f0ad512877c0b','091f5cf6e9ec7a340325cb68ea74d430']"

   strings:
      $hex_string = { 3e8399282bf1cd97a2bd18aa8536ac76afce09d8fc7f122dd978fd6e7d1eec72548a84b244328b0ad23048cc22d4b8c54e0b33ae02c8d14c04f7d62975950580 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
