
rule i3ed_11eb5e4b48800132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.11eb5e4b48800132"
     cluster="i3ed.11eb5e4b48800132"
     cluster_size="79127"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit starter bpng"
     md5_hashes="['000140499c03984400e4cc0d02555c83','0004617ebe49f2cb275a89f80a102825','000d6504f2a3425c5bf705734da09e90']"

   strings:
      $hex_string = { 744c6173744572726f72000007014765744d6f64756c6546696c654e616d65410000fd0152656c656173654d757465780000bb026c737472637079410000bf02 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
