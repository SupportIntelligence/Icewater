
rule m2321_491f1ca9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.491f1ca9c8800b16"
     cluster="m2321.491f1ca9c8800b16"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik razy"
     md5_hashes="['20ba58c33db7eacd2b812195c0d35c3f','2ffdc48406af306385925456ab6acecc','dea9206bce2594c8cea3c2cc4303ab4b']"

   strings:
      $hex_string = { 4c6b8caded825af8affde58beb9bdcbaff29d8bc779d6fda926e831ca201c8d00a0eae3f2abe1921b286250012992091288d4724b35e7a8aeea511134440943d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
