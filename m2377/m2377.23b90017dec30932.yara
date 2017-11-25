
rule m2377_23b90017dec30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.23b90017dec30932"
     cluster="m2377.23b90017dec30932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['5cb3dbe4c755d089c4de2c4bad5271ae','6216378bc1fbb669390bfdf9ef8674dc','c7def8d58ca71c7c7855e7adf9eb8e30']"

   strings:
      $hex_string = { 43687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e642049 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
