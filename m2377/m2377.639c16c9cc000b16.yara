
rule m2377_639c16c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.639c16c9cc000b16"
     cluster="m2377.639c16c9cc000b16"
     cluster_size="35"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['019463f161b5ef109a0f0bfbb362ff14','09458d32898455b4df3983a93bd95fd3','7315b9b462ad4e30c1bd1251c85d9036']"

   strings:
      $hex_string = { 01a4c9c629686b1dbfdb4226369354fada2d5de8c399b56c0aa5f227b74eb2b3f55e3f13e69ac79feb52a68c0646287e34a2bb49ecce85457783676feef3c216 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
