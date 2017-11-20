
rule m2318_39b9200ddda30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.39b9200ddda30932"
     cluster="m2318.39b9200ddda30932"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0e40a922e5e88b92f85eea59fdd62df3','6f49b645a93a515598d3345bc3a723e5','b38da743d8dff937c45f1f53d399c354']"

   strings:
      $hex_string = { 43687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e642049 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
