
rule m2321_291a944aea608b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291a944aea608b12"
     cluster="m2321.291a944aea608b12"
     cluster_size="7"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut shodi midie"
     md5_hashes="['2fc9b87e70b606b2a2d07085531b3d2a','5709a85dade50fd64932f0f452c2a323','d60158a4da82664d605dfe395f32333c']"

   strings:
      $hex_string = { 5fd3c2daa218afe658c33355d75461a94db99ab57ebf477cf214f1c9e04f908909b7bea83a4e39f8dddbb11cc86552249372a76d7d8e84680c2c27d4d274f5ce }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
