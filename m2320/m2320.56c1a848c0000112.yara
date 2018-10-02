
rule m2320_56c1a848c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2320.56c1a848c0000112"
     cluster="m2320.56c1a848c0000112"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="macro valyria powload"
     md5_hashes="['011c0b448d770a7f81a5f3308b8beb6fe15991d3','d2f88859232b75115ef3ae23727dbaa707823238','dfabdb72e855fc7097ac07c1ee96303a031672d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2320.56c1a848c0000112"

   strings:
      $hex_string = { 9a536afda432fa6b4dc9c5433e95705b3c6675244820d5d17206840802b646176dff0010e9efab98335ccc31120f8cd5f0eaaafb0d048abdc261b1d7fe2994b2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
