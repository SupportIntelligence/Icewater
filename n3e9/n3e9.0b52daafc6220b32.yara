
rule n3e9_0b52daafc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b52daafc6220b32"
     cluster="n3e9.0b52daafc6220b32"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious arnno"
     md5_hashes="['156a3dfadcc811568590006dbf1b1e9b','724d0c071fb641d4af58907137e1ab78','c7ef7e1b73d366d1879d39e0894d6d27']"

   strings:
      $hex_string = { 00070043006f006e006600690072006d0004002600590065007300030026004e006f0002004f004b001700490063006f006e00200069006d0061006700650020 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
