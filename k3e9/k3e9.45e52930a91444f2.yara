
rule k3e9_45e52930a91444f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45e52930a91444f2"
     cluster="k3e9.45e52930a91444f2"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['3c26b6fbcee2773194a99b1e9ef28272','41114edcf1c6877c9bff66f345d7d2cb','f1bbf6092db77e535a303736244f4de4']"

   strings:
      $hex_string = { 5e65af057886827e3e484a4ea64330575b63af0b7d898b8a4d4b496a555138585c64af29888c8d926d313c3a53503b595d1705768f8e90948456473f0234376c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
