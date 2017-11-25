
rule k2377_2b934d49c2220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.2b934d49c2220b32"
     cluster="k2377.2b934d49c2220b32"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html exploit"
     md5_hashes="['474b44760b9c575d2e4ef70871c52675','768c4bb458a1bf543eaed9f63cbd53e3','f8ef45a3070b641d3c82a9dabf2d18f9']"

   strings:
      $hex_string = { 3c7464202077696474683d223130302522207374796c653d226261636b67726f756e642d696d6167653a2075726c2874656d706c617465732f6e69636865322f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
