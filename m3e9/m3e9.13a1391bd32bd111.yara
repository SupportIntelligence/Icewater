
rule m3e9_13a1391bd32bd111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13a1391bd32bd111"
     cluster="m3e9.13a1391bd32bd111"
     cluster_size="64"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['0a551ffef669e575a572cd7a5822dac8','16db82a26c3f54f43e6d54df90293272','42083470b73e0dd53c1cc1efe2ef270c']"

   strings:
      $hex_string = { 21b7ee1cbe8d017866a75ac5edd3ff426fe304faa54a76e82ad5cb9686db3065fbcf4170c25e61f4d76055a835093d89c0a6001149404bb8e2e7c71be423826b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
