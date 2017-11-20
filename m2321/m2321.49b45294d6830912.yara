
rule m2321_49b45294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.49b45294d6830912"
     cluster="m2321.49b45294d6830912"
     cluster_size="20"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['13f158856b7d13d91cbddf84b6d73cf0','15b2fe5a87124db3d120ff72af0baf7f','f0c361c05d9060d9cc425195f9291f2a']"

   strings:
      $hex_string = { 8b1018edee984b67f2df8771a1230c645b49177dc659f9c59bb421f6cd2aab53f8aac9bc3b8034d0243799b7e1b6d3bae694827a630a2a1adc831b4f01fa7f1c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
