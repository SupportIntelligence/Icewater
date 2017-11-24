
rule n3e9_13ab1be14a001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13ab1be14a001116"
     cluster="n3e9.13ab1be14a001116"
     cluster_size="139"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun vilsel"
     md5_hashes="['07a86cb16aac3ab5e73adcc821675d16','07d7744efff350c8f25a9244845f6a54','3e3fe259aecaba594aac7fc06e0c7569']"

   strings:
      $hex_string = { 106d90fef15f8c76f8735d4a0c75ce52d2ca1d689634ab38de4d9377b1d801efee89ff6e959ec46ce40ba533c794ebcf8a4885c4f4000e67222f167e089a4232 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
