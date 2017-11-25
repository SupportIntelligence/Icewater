
rule n3e9_2b1894f9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1894f9c2200b16"
     cluster="n3e9.2b1894f9c2200b16"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler riskware"
     md5_hashes="['06e4a12551b7f6b840a824c9e6551435','10f6fd7eafdfe30d1c5bb3c4444541b5','ce9d1d5b2988c1ac76e7b39d36541565']"

   strings:
      $hex_string = { 0043006f00640065003a002000250064002e000a00250073001b0041002000570069006e003300320020004100500049002000660075006e006300740069006f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
