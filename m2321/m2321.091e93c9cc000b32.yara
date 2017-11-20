
rule m2321_091e93c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.091e93c9cc000b32"
     cluster="m2321.091e93c9cc000b32"
     cluster_size="74"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar virtob shyape"
     md5_hashes="['03bb1f17985562b33e65e144cdd821a1','04861f4dc294ead8972484ae1e894a1e','2df5a58efcd64cd1f1e4b7403b3c804a']"

   strings:
      $hex_string = { 7a52e10714cf982a27188f9b871ae64935e443c53de8f296864c454f938cd392e31fd05c5efcc0579cc751835630bbb65a6028349e81610872e96982a14250e0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
