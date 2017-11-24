
rule n3e9_1ba35ec348001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1ba35ec348001116"
     cluster="n3e9.1ba35ec348001116"
     cluster_size="192"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun vilsel"
     md5_hashes="['04b04dcb0f805295f5274fbee0e478be','07890c8a5ba1fcc02ef610c5b5fc1fa4','3a00eecfc15ee19b0af6955255b54da6']"

   strings:
      $hex_string = { a27a2e0b5034ae33f2ecc16ce686f96d710ec3000cf429b759780cac76d9a687a5c0856b382294bfd6e04ddac202577027ea452f5a48f8f690935f1131afc8ab }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
