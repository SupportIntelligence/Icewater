
rule m3ed_45762a1a12cbc291
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.45762a1a12cbc291"
     cluster="m3ed.45762a1a12cbc291"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul cosmu"
     md5_hashes="['0939654d37e4c94c460b198abd69f796','1742e43ac17f79fea461cd27f612c4ce','dcc15206d1869cdad413c3b4837e3c68']"

   strings:
      $hex_string = { c60fb6379903c813ea8bc18bd547ebc95f5e5d83fb2d5b7507f7d883d200f7dac353568b74240c0faf74241085f6578bde75014633ff83fee07739833d984c03 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
