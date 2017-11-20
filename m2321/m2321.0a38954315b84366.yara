
rule m2321_0a38954315b84366
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0a38954315b84366"
     cluster="m2321.0a38954315b84366"
     cluster_size="21"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod kazy trojandropper"
     md5_hashes="['00bf9e1c01bbf1fe96ed1f7302ddc65d','0672c8d762ba8f9b2a385745c296da3a','ce7b204f42bcd76e9e069b728591d0e7']"

   strings:
      $hex_string = { 21eaebd02404f92ca3282e6b208fbaa79ce4d42910a841e1cc132dedb8694d64a2d70551e3d29979b285ca9b1adbc963782a19390834af466183e07584c6936d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
