
rule m3e9_439c7169c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.439c7169c0800b32"
     cluster="m3e9.439c7169c0800b32"
     cluster_size="1651"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['001c2b64a71e798b30738abebe040d3b','0033fc0e43718adc9f9e5e343c699afe','0410fcb0d7e646858efc227310717c16']"

   strings:
      $hex_string = { c7025756ff75e06a01e8c80b000083c41c85c0746c8b75e466891e833d5ce30001017e36385dee74318d45ef8a103ad374280fb648ff0fb6d23bca7f168d544e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
