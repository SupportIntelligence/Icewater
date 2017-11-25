
rule k3f7_09b8944a9ae30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.09b8944a9ae30b32"
     cluster="k3f7.09b8944a9ae30b32"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['3831338bb2e4b32cdbfa5d77f1b15370','4fff70f39533e14d34d984c9a28c1259','e2008170c7053e2c2613aa00eb14a460']"

   strings:
      $hex_string = { 3d27746578742f6a617661736372697074273e0a2f2a203c215b43444154415b202a2f0a766172205f7770636637203d207b226c6f6164657255726c223a2268 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
