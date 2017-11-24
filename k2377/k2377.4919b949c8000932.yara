
rule k2377_4919b949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.4919b949c8000932"
     cluster="k2377.4919b949c8000932"
     cluster_size="56"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['081bf90517a7b33aa1f5cb2a21aa7bf9','08ad3f538c934193a6eec516811c37c7','3983c188ec078d7e4f92e8d13f204dda']"

   strings:
      $hex_string = { e9d1e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
