
rule k2321_0ae89c540e6b48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ae89c540e6b48ba"
     cluster="k2321.0ae89c540e6b48ba"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['494e3461f8b6c4be64edf9ec5b859e56','7f3743322fe51b86c1857a51151b4b95','9fb11039ac367b8679f635d389cb23b2']"

   strings:
      $hex_string = { 70bb29794bf7667d0e3ed5b0b8e7c3cf2d933cd7e1d19b118ce09ce4836384a937df042c97af013e959ab3756ceefae65cef7465d8c8155b228a5ff4c234f672 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
