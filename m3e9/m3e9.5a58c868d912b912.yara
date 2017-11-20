
rule m3e9_5a58c868d912b912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5a58c868d912b912"
     cluster="m3e9.5a58c868d912b912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="carberp shiz kazy"
     md5_hashes="['2a686a96e0a99a761a23cf913041e91d','60a429c8e3c1103bb48264a2480fc8da','7fa56b4fc173b41215e6ed507ce21bf9']"

   strings:
      $hex_string = { d3df3eb5c7602a754acfada6075fedd6252c627391b0be633b59807bea45e122bf3cf743f31a1ba18587e34d06f6a893578f4736d016b769e47233c5412b5608 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
