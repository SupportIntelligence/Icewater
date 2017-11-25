
rule k3f7_2b947b42d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2b947b42d9eb0912"
     cluster="k3f7.2b947b42d9eb0912"
     cluster_size="15"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['01bc590e52e3c6a2ef3185e7d9cee56d','1c8ab44b82a9283399a24022aeb44214','f8db7618e5812308e619365646b404f9']"

   strings:
      $hex_string = { 3d27746578742f6a617661736372697074273e0a2f2a203c215b43444154415b202a2f0a766172205f7770636637203d207b226c6f6164657255726c223a2268 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
