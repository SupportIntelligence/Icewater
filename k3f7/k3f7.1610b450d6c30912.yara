
rule k3f7_1610b450d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.1610b450d6c30912"
     cluster="k3f7.1610b450d6c30912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['17690261184aee1c95f72ca5b6f03da0','263a106ef2006fc873083a550b8aa061','795a03e8c2a57a79e8cd48075d891f0c']"

   strings:
      $hex_string = { 3d27746578742f6a617661736372697074273e0a2f2a203c215b43444154415b202a2f0a766172205f7770636637203d207b226c6f6164657255726c223a2268 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
