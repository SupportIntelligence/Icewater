
rule k3e9_6c1496e33ac10b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6c1496e33ac10b14"
     cluster="k3e9.6c1496e33ac10b14"
     cluster_size="2934"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt zusy injector"
     md5_hashes="['0068f366645cc384049836be8fe71de5','00a768c8f5003a882122c5d56c80ec5b','02688986752197e6a3a2a4eb8b90000b']"

   strings:
      $hex_string = { f6746f155610df14689b815ca7ab60f124219ab0b8277cd38de36e40f344cb5f46ed2b3690c0d21dbde432dccf1b1960efbc9fd4a118eb3b7d925b352a9ed589 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
