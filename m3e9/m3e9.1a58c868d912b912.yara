
rule m3e9_1a58c868d912b912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1a58c868d912b912"
     cluster="m3e9.1a58c868d912b912"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="carberp shiz kazy"
     md5_hashes="['12dad930e73332acf3bf5a46c84fc636','15d902b3d7046d2eb1d0d7c13986a728','f9385eb3f5dd8cfc2fd844572a4e9adb']"

   strings:
      $hex_string = { d3df3eb5c7602a754acfada6075fedd6252c627391b0be633b59807bea45e122bf3cf743f31a1ba18587e34d06f6a893578f4736d016b769e47233c5412b5608 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
