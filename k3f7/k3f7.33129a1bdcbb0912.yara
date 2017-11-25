
rule k3f7_33129a1bdcbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.33129a1bdcbb0912"
     cluster="k3f7.33129a1bdcbb0912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink script html"
     md5_hashes="['0552f4740717ce6cb91e454b38bf7883','355073f9bc74a3595a965484498b71ca','90259f111be9d0b404684f3ff256f996']"

   strings:
      $hex_string = { 3a2022392e302e30220a097d3b0a09536861646f77626f782e696e697428736861646f77626f785f636f6e66293b0a2f2a205d5d3e202a2f0a3c2f7363726970 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
