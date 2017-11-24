
rule k2318_49065cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.49065cc1c4000932"
     cluster="k2318.49065cc1c4000932"
     cluster_size="25"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['1685d20a70461c5ef59bb9045af4bba6','232042ffa1d5b0db613a3a75c5262f6c','b9a8f6e1ad0dfb65ec8d1245ca61c667']"

   strings:
      $hex_string = { d1e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
