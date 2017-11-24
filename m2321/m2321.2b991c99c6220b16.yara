
rule m2321_2b991c99c6220b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b991c99c6220b16"
     cluster="m2321.2b991c99c6220b16"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut midie shodi"
     md5_hashes="['574df8f094723bdc62ba079ffec206aa','820e3b6ca20f03ef387ad117fd34e466','b35c0c78c9bae7f4c9651890a2dd38e0']"

   strings:
      $hex_string = { 4299fb22755fc8b1390ccdd744c94d0489836ff954bc6c90cab6f1f00ac0c5112709b0144b106ba1bbfd469cdb9a95cb4f2faf8a5477a07230029e3d5b7b79b5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
