
rule m2321_13981718dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.13981718dee30912"
     cluster="m2321.13981718dee30912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery emotet pemalform"
     md5_hashes="['2f595a3f4e31ccb578c38249fedc1d74','3e711a6e2a18048fc65a225eccd97553','c1e869703935a7ad66f2501de01034ad']"

   strings:
      $hex_string = { f78b31205f1987c304641f91b3ab0b38d177584ecc8982e6575a7190a15e1a216c86e7e072feb96c392551367f03344bc601c433d8fadbb8c2efd47adf3ff92d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
