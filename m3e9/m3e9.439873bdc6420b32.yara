
rule m3e9_439873bdc6420b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.439873bdc6420b32"
     cluster="m3e9.439873bdc6420b32"
     cluster_size="88"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['0335be8e5255e598b139e951b423658e','130f61d1751408c3959c1f8067292f33','a4612023d9eb23c99a9e8bb3d5528fb1']"

   strings:
      $hex_string = { c7025756ff75e06a01e8c80b000083c41c85c0746c8b75e466891e833d5ce30001017e36385dee74318d45ef8a103ad374280fb648ff0fb6d23bca7f168d544e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
