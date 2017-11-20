
rule m2321_091e95a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.091e95a1c2000b32"
     cluster="m2321.091e95a1c2000b32"
     cluster_size="23"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar shyape virtob"
     md5_hashes="['059fa33e16338a76377143f83bc852fb','0cf15e2fa8275f1d0c229ffc8c0fec9b','9ad96ca6d2c2dd73ff75a66181e919d5']"

   strings:
      $hex_string = { 7a52e10714cf982a27188f9b871ae64935e443c53de8f296864c454f938cd392e31fd05c5efcc0579cc751835630bbb65a6028349e81610872e96982a14250e0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
