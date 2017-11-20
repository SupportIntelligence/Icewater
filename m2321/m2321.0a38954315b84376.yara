
rule m2321_0a38954315b84376
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0a38954315b84376"
     cluster="m2321.0a38954315b84376"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod kazy trojandropper"
     md5_hashes="['4dac99bb93318788120f574dba453803','8dfb0a15456d0e4f7cc9ee8e7be06ad3','d0490bca4d08d45e5ff10720a7c4bb32']"

   strings:
      $hex_string = { 21eaebd02404f92ca3282e6b208fbaa79ce4d42910a841e1cc132dedb8694d64a2d70551e3d29979b285ca9b1adbc963782a19390834af466183e07584c6936d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
