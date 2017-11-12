
rule m3e9_5a949cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5a949cc1cc000b12"
     cluster="m3e9.5a949cc1cc000b12"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dapato razy virut"
     md5_hashes="['091faf4509fe39fa21317cc4c1579bfb','0a71249e547a886dea5029bcb9a3c552','530b0891181ad5a64ccb5d7b65a01ec1']"

   strings:
      $hex_string = { 8040003058400018000000525344534904820e68a3ea4fb8b0ba011732d7c001000000433a5c446f63756d656e747320616e642053657474696e67735c41646d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
