
rule m2321_5b5cc868d912b912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5b5cc868d912b912"
     cluster="m2321.5b5cc868d912b912"
     cluster_size="71"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="carberp shiz kazy"
     md5_hashes="['13293184d2c34ae675d15bc5e040203a','1cf5541ef262e5b6c8ba941b2b1af9df','4207e5051ff62d2e0a4ecbbce17e5f7a']"

   strings:
      $hex_string = { d3df3eb5c7602a754acfada6075fedd6252c627391b0be633b59807bea45e122bf3cf743f31a1ba18587e34d06f6a893578f4736d016b769e47233c5412b5608 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
