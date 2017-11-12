
rule n3f0_224b685430c144f6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.224b685430c144f6"
     cluster="n3f0.224b685430c144f6"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira ccpk icgh"
     md5_hashes="['d3eb75e0112abfdedcc675bd5f452004','da9656a1da8eba06dc9b2e48e8596f3b','e9bdc0bf924e9d589c1e3345f55c0bcf']"

   strings:
      $hex_string = { 3dc55d3b8b9e925a0d65170c7581867576c9484d65ccc6910ea6aea019e3a346bcdd8ddef99dfbeb7eaa51436fc6df8ce980c947ba93a841bf3cd5a6cfff491f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
