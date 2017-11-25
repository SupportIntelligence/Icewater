
rule k3f7_49065cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.49065cc1c4000932"
     cluster="k3f7.49065cc1c4000932"
     cluster_size="516"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['00a6da3b51e4eb11195d1d7c0c10ca55','00cb3f16447d30191be2624e554f586a','06bfd71863edf17a39529e3baf3d3198']"

   strings:
      $hex_string = { e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
