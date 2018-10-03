
rule o26bb_5b90d9a294bb1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.5b90d9a294bb1916"
     cluster="o26bb.5b90d9a294bb1916"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mikey ardamax keylogger"
     md5_hashes="['730adcf320ee4e88867f3d5f8a49da365041e825','c4904559bef5330db238ecfd23fdc0999deb28ac','590b5cd05ceaf40f33ee78785962bb3e6f3767a8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.5b90d9a294bb1916"

   strings:
      $hex_string = { 0fc93b008040c020a060e0109050d030b070f0088848c828a868e8189858d838b878f8048444c424a464e4149454d434b474f40c8c4ccc2cac6cec1c9c5cdc3c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
