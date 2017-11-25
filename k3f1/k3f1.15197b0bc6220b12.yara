
rule k3f1_15197b0bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f1.15197b0bc6220b12"
     cluster="k3f1.15197b0bc6220b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mydoom email cjdz"
     md5_hashes="['0c28fa19198a4e1aea23a8bbbf2440a6','11153ecfbd6ca4e1f8bb45b90d38e1f9','e0ae5cec8795f28d76c0047d52ebf5b4']"

   strings:
      $hex_string = { 50dfefb6b31a54ce0c410f56c64605015268d3fdb5ba590902e02300760726580ec9cd2267af60bf27dd96f805eb4b7e2c7520102b1d2eda2866b9066a481b15 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
