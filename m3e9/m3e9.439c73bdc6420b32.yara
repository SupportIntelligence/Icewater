
rule m3e9_439c73bdc6420b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.439c73bdc6420b32"
     cluster="m3e9.439c73bdc6420b32"
     cluster_size="94"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['28487db74495cb67db688cc9b4253627','645feebc7c29992adb3143132843f7b0','b22e1e7b94942dfa3eecfdf931232910']"

   strings:
      $hex_string = { c7025756ff75e06a01e8c80b000083c41c85c0746c8b75e466891e833d5ce30001017e36385dee74318d45ef8a103ad374280fb648ff0fb6d23bca7f168d544e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
