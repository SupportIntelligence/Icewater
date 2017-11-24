
rule m3e9_1493eb26942b9b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1493eb26942b9b12"
     cluster="m3e9.1493eb26942b9b12"
     cluster_size="32"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious dldr engine"
     md5_hashes="['03d4c51d30f4d7a1da15b0c67f511e4d','08e42b8de5764fa6989a0681d523fb8a','9173fc4de42784feb1514433a8635f09']"

   strings:
      $hex_string = { 8d46185750e810cdffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
