
rule m3e9_19b9200240001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.19b9200240001932"
     cluster="m3e9.19b9200240001932"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmu hamhuf anhf"
     md5_hashes="['12ff5be56d8217da986c21d09fbcfe5b','130180ae795f5bc9f37df5b055f69891','b64d35b83a71553e902ac14682cf9ed2']"

   strings:
      $hex_string = { ac06530bbd8436a9f9a8df38014eb64f249ca521c2a4f185793cdc2ab75f109b6429d4f6b9e1e4fd92d6356260b2cde63d71830478ffdb58199850c51d481e51 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
