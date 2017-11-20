
rule k2377_4905b849c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.4905b849c8000932"
     cluster="k2377.4905b849c8000932"
     cluster_size="16"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script html redirector"
     md5_hashes="['0209209c2f650c9459518e1d5168b167','11d8bdc7b13031061f147918937734d6','e799bd026696f98d42eaf7851e56c904']"

   strings:
      $hex_string = { d1e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
