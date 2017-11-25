
rule n3e9_13a8613902201116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13a8613902201116"
     cluster="n3e9.13a8613902201116"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun zepfod"
     md5_hashes="['027dd5fd04f20f2ccf734e89acad4069','1bf84c91006d421887564557766152ef','d5f24a1c6ec3772d5fcf22d0ba95824e']"

   strings:
      $hex_string = { a27a2e0b5034ae33f2ecc16ce686f96d710ec3000cf429b759780cac76d9a687a5c0856b382294bfd6e04ddac202577027ea452f5a48f8f690935f1131afc8ab }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
