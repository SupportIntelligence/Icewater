
rule n26e5_2910a28bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.2910a28bc6220b12"
     cluster="n26e5.2910a28bc6220b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="filerepmalware malicious risktool"
     md5_hashes="['2f236e351312adb9c6218a8a625de464cd8aa274','cf1b278c86a48fd37296b054713317995698a607','c0a0295d0e73beea4fbd40929c5742f5a7ca384b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.2910a28bc6220b12"

   strings:
      $hex_string = { 02f1f40863db80e2e51ad6c2f9cd9b8652271c728fa6f506596f61d305d1674f5a0144e625400a17f68ba1416f1eab2e75b583d069a32912d271feec66ed30cb }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
