
rule m3e9_439871e9c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.439871e9c0800b32"
     cluster="m3e9.439871e9c0800b32"
     cluster_size="1477"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0002604d9714c2f43d1600d223ed90a1','00577ecc24b9d505dbd8117d8a90918f','03dc71db0e317f9f169076606672f4e6']"

   strings:
      $hex_string = { c7025756ff75e06a01e8c80b000083c41c85c0746c8b75e466891e833d5ce30001017e36385dee74318d45ef8a103ad374280fb648ff0fb6d23bca7f168d544e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
