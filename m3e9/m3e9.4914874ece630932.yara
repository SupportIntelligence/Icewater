
rule m3e9_4914874ece630932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4914874ece630932"
     cluster="m3e9.4914874ece630932"
     cluster_size="2331"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt vobfus wbna"
     md5_hashes="['003268f9e4f80f230f0f4fa0d823bde9','0067b523bd489bd8057903bac7f3bc0f','02e2756f6fea4c0cd11f4aec2c19f596']"

   strings:
      $hex_string = { 114000508d95c0feffff528d85b0feffff50ff1554114000508d8dacfdffff518d95a0feffff52ff1554114000508d859cfdffff508d8d90feffff51ff155411 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
