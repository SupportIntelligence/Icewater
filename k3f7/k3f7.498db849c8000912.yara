
rule k3f7_498db849c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.498db849c8000912"
     cluster="k3f7.498db849c8000912"
     cluster_size="274"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script redirector html"
     md5_hashes="['00205258fb6693f77eef42a1a02d424a','036c59d8b964fce1e8e9fed95cf3cc80','112bafca164a497993c9173e31a232ac']"

   strings:
      $hex_string = { d1e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
