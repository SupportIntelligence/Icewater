
rule j2377_49051cb9d99d0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2377.49051cb9d99d0912"
     cluster="j2377.49051cb9d99d0912"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe exploit blacole"
     md5_hashes="['43b77971ba83d955fee54af931781508','6ea397b5e79d6a0d2c9d852830180e51','9e1c22266ca12c5ff528da7c9ab85d8f']"

   strings:
      $hex_string = { 223e093c7363726970743e69662877696e646f772e646f63756d656e74297472797b6c6f636174696f6e283132293b7d636174636828717171297b7a7a3d2765 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
