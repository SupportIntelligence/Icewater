
rule k3f7_49b90cc9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.49b90cc9c4000932"
     cluster="k3f7.49b90cc9c4000932"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['32d83fcef431c3e5a3b113353032504b','4732e99560a9d2fe1d1fa15ffff30507','e939d9b9ba28aee6174a51ad2398a87d']"

   strings:
      $hex_string = { e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
