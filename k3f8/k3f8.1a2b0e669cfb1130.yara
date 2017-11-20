
rule k3f8_1a2b0e669cfb1130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.1a2b0e669cfb1130"
     cluster="k3f8.1a2b0e669cfb1130"
     cluster_size="161"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="smforw androidos smsspy"
     md5_hashes="['002810630f2f916db555c7d1e9d02748','00b081501d54fb4c5c5709b1804f841d','11708d253d2b3c4563fb1f69a9cb5393']"

   strings:
      $hex_string = { 0226683c025b1de1030fb3035c5a0113102d1e2d692850030e9b032c6e3c2d1e2d834e030d9a032c6c3c88011914026a4a050da50312ad055ca5011017051206 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
