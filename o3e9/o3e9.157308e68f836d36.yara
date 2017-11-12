
rule o3e9_157308e68f836d36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.157308e68f836d36"
     cluster="o3e9.157308e68f836d36"
     cluster_size="742"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0009c4d5e0ba763bfc5dc1692122ca11','009067301c02225acf79544627a31d65','05d8c27f3d0650d63a1439eac199db75']"

   strings:
      $hex_string = { 4d32c994e483c2df3ac8e664c9eadc2fa7dff095e9480c0160574a6bac630297efe0fb5f6922b05c65786211dfd90ba1611297bffd5f2b80cfb3c258e4143441 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
