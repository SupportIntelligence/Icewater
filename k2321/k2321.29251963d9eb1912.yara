
rule k2321_29251963d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29251963d9eb1912"
     cluster="k2321.29251963d9eb1912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt symmi"
     md5_hashes="['1ca732a2016f99c613b4076b3af894a3','282df30f6896079c7100899f64b756ec','e8a667f1ef2df4513e4efe439f5ff999']"

   strings:
      $hex_string = { 17a1e3185e7b46411bd4c53ea04dd10b6b6c84dba5c3f682c930ac5d15e1032acd00a6794aadc741e012d7e40d29545a92779e67c4766c07bb323d21b63513ec }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
