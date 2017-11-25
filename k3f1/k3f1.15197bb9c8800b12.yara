
rule k3f1_15197bb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f1.15197bb9c8800b12"
     cluster="k3f1.15197bb9c8800b12"
     cluster_size="37"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mydoom email emailworm"
     md5_hashes="['005daef074f38f872d39a402215f6bad','0a9e857c0ae4a12a7d49a40b643de12a','798139c000f6d915f769a02f9b7c7e87']"

   strings:
      $hex_string = { 50dfefb6b31a54ce0c410f56c64605015268d3fdb5ba590902e02300760726580ec9cd2267af60bf27dd96f805eb4b7e2c7520102b1d2eda2866b9066a481b15 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
