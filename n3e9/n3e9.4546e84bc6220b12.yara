
rule n3e9_4546e84bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4546e84bc6220b12"
     cluster="n3e9.4546e84bc6220b12"
     cluster_size="19"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious heuristic engine"
     md5_hashes="['29f7d545a484ed1f349550102a7af604','2d732d6dbaf1f2a02dbb7a07dadf8894','f26a6340aa43538a45b1d6240675e58a']"

   strings:
      $hex_string = { b9c8a78d188c120ee4956469cb79c5726d1b2d2913abd2d4a1ce8e54d96d499e1f937d4d52c9ecfdef2e6b2b5b47eae3b83c4515763134e1d7c6f2bc5c41d128 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
