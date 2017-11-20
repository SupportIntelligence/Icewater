
rule m2321_491c7294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.491c7294d6830912"
     cluster="m2321.491c7294d6830912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['1c859a0b77d6c2af7c7007ffb53f1f31','1ef07ae9a976bf6688216c6b3df98795','c5ddbe749b956ea80cdd5e7233cc455b']"

   strings:
      $hex_string = { 19683fe348f6bfdb3c456a6b5a92eb97a51d7f1f3eb0f02947158441ed8db2fbc1d2fe21c0c3631b0bb72314a6aee0f717027971dab56cb24e75315681743a9e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
