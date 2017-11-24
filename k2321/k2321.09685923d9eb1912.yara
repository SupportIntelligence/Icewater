
rule k2321_09685923d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09685923d9eb1912"
     cluster="k2321.09685923d9eb1912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['092ad8f8c48c6760fc91d66564f59378','15c2bdd346cc4368e3a804a1004373d0','bd4584d1551d6628b0bdd411f40c55da']"

   strings:
      $hex_string = { 3ecff5e661ccd7abe933f4d070648d88d61946a7fdddc7d97f4768faf84248327eaf538eed9511dfe1dc9d9cc339ea2b5b9fc76dce278f238a868b7ac0e2981e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
