
rule k3e9_6ac2979c16536bd2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6ac2979c16536bd2"
     cluster="k3e9.6ac2979c16536bd2"
     cluster_size="36"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis malicious"
     md5_hashes="['001a466b144741d525cf7761cd8e5bcc','0e2d9f2439e06b94ed2174c6ec26432c','54d12d9b4e2b66c69bf416abc8d13f5c']"

   strings:
      $hex_string = { aa39af39b5393c3ab33ac23ad83aed3af93a433bc33c2a3e763e803e9a3e7c3f000000200000ac00000037303e30b7302e317532dc32ed32fd321b3322334433 }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
