
rule m3e9_316339774deb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316339774deb1112"
     cluster="m3e9.316339774deb1112"
     cluster_size="64"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0455d2c1da99961e6bae36601c35b868','08aad434facbbde03edd852aae6350ea','54d2ef7cfbb1177feb2f2cf24423d5b4']"

   strings:
      $hex_string = { 1f065e9a6f10826dbeadedd5ea5c340e95412fa587598cdecba4a0fa71ef1bd70d25fb19b4849316daf08dc93581ba3654bd8eeb4a4b5b05c0646896c132e166 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
