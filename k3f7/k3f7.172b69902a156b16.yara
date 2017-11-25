
rule k3f7_172b69902a156b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.172b69902a156b16"
     cluster="k3f7.172b69902a156b16"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['2c55a126e4b14e6362cda2b7481cb705','6d33845f54e0ff489d7ffcfc318f9f68','ee78f2e76e7320bc80b96d0024278f0f']"

   strings:
      $hex_string = { 3d27746578742f6a617661736372697074273e0a2f2a203c215b43444154415b202a2f0a766172205f7770636637203d207b226c6f6164657255726c223a2268 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
