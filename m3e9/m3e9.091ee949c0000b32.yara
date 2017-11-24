
rule m3e9_091ee949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.091ee949c0000b32"
     cluster="m3e9.091ee949c0000b32"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar shyape virtob"
     md5_hashes="['2e76ba4c8ec6315676a398c67c596d2c','417e2ef6c641050ee9d25b6c68aae873','feac14109803f83c71ab07a79eec4568']"

   strings:
      $hex_string = { 7a52e10714cf982a27188f9b871ae64935e443c53de8f296864c454f938cd392e31fd05c5efcc0579cc751835630bbb65a6028349e81610872e96982a14250e0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
