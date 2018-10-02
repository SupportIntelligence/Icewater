
rule n26bb_2b48a699c2220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b48a699c2220b32"
     cluster="n26bb.2b48a699c2220b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious heuristic"
     md5_hashes="['8af8a34b81bfc2db486b1a284f699c89a5131d28','935ff6e21b5f05b10e7fff3aeb431a2078d38cb0','e9602ef39bb168cf77cd9dd2695eb62f4c125288']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b48a699c2220b32"

   strings:
      $hex_string = { 4772616469656e74496e61637469766543617074696f6e000000ffffffff0a000000636c47726179546578740000ffffffff0b000000636c486967686c696768 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
