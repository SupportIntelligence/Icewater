
rule m2377_1191344bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.1191344bc6220b12"
     cluster="m2377.1191344bc6220b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script embtfc"
     md5_hashes="['06d8dceb01797bc182956770e8a57a17','93270d97bcba1aaf14e35cbb6dbaa4e6','e45036fe748541353b1b4f2e1c2336e1']"

   strings:
      $hex_string = { 3d27746578742f6a617661736372697074273e0a2f2a203c215b43444154415b202a2f0a766172205f7770636637203d207b226c6f6164657255726c223a2268 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
