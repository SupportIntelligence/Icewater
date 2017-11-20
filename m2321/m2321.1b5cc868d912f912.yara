
rule m2321_1b5cc868d912f912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1b5cc868d912f912"
     cluster="m2321.1b5cc868d912f912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="carberp shiz kazy"
     md5_hashes="['1810d2a752bd3f20208e0791c1220e5c','64f94e691754f97d05091eb49f3cbd5f','fadc540a088470c0448ab857d54abf1d']"

   strings:
      $hex_string = { d3df3eb5c7602a754acfada6075fedd6252c627391b0be633b59807bea45e122bf3cf743f31a1ba18587e34d06f6a893578f4736d016b769e47233c5412b5608 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
