
rule m2377_635b2008d9ab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.635b2008d9ab0912"
     cluster="m2377.635b2008d9ab0912"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['14538363d7196da3158fb57497c3e938','8cce02ad9e76b83caf987105f58064b2','a6388c1cc982ea8e7266b6e6f5c8eaa1']"

   strings:
      $hex_string = { 6a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
