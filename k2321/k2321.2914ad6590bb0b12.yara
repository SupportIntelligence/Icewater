
rule k2321_2914ad6590bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad6590bb0b12"
     cluster="k2321.2914ad6590bb0b12"
     cluster_size="7"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['24f73f8cbffc560703336014bd9d296a','55b2a5cf15dd297a698a225ba7287b68','fa00fcaa5f7c20db37472d8ec75b2aeb']"

   strings:
      $hex_string = { 94a44913c6972d58b07dfbb60f3ff8f0d34f3fdbb367cf6e3c3ed9fdc927587cf2f1c71fbff5d65bab57aeca9e9c39a077efd88808201aac5685eb83a34243a2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
