
rule m3e9_13b92b2098bf3912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b92b2098bf3912"
     cluster="m3e9.13b92b2098bf3912"
     cluster_size="75"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot lethic shipup"
     md5_hashes="['01e7064eb7af6ffbc1c953a4f2ef4172','092f0b77b276617b6ada6cc2b112b967','8c75b93ede9226f7fb19b37748b75ffa']"

   strings:
      $hex_string = { f3dccc1bd70886a6755a636633aa635c767823f2d6fb03f23503abccc4e4b3ab8f3dc4977db31800006f759a635167742d5d759a74b5b7fb03f235c3aa8cc2a4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
