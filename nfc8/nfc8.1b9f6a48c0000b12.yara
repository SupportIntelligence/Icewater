
rule nfc8_1b9f6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.1b9f6a48c0000b12"
     cluster="nfc8.1b9f6a48c0000b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos smssend smsagent"
     md5_hashes="['fe04b9dd0b19ab55d7fdb45bfc9ba43e20d5d7f0','770e7da1f131ff7a9ce8265554efc192ac080e48','0ecb0a7e4ce9a307ea962bc32c365f8a56c9136b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.1b9f6a48c0000b12"

   strings:
      $hex_string = { 94ceb4c6aa2435fbd2467a87a2e86b37df5ca595e78d2751588171d3395f76c7a0b56064750503430edbf77d114fecd98ad7bf7a23def8baf5a854063b5d2cca }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
