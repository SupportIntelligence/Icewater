
rule m3e9_439873bdc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.439873bdc6220b32"
     cluster="m3e9.439873bdc6220b32"
     cluster_size="285"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['00a85bcadd8a1ae3fe41b19a16c32b51','0110a41f896006a5efdb0d499b343c38','05ebfe1573e371c19aa445c8c73a74a7']"

   strings:
      $hex_string = { c7025756ff75e06a01e8c80b000083c41c85c0746c8b75e466891e833d5ce30001017e36385dee74318d45ef8a103ad374280fb648ff0fb6d23bca7f168d544e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
