
rule m3e9_4c1e329986620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4c1e329986620b12"
     cluster="m3e9.4c1e329986620b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['375937255d21dde898fa982368bd0ccb','4012bef9ce10e5b6c8f4b1b07f0c5138','db4fe792aea421248e936a80bb78775c']"

   strings:
      $hex_string = { bee21affadbd790ac7bff31bd838f6c358bbed937cec8603ede5a54efef2994bfd617f040c479ce79acc3023b5d0d54977012a6d082589c0fb6b823650e42e98 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
