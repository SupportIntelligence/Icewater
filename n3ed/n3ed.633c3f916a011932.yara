
rule n3ed_633c3f916a011932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.633c3f916a011932"
     cluster="n3ed.633c3f916a011932"
     cluster_size="120"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo browse"
     md5_hashes="['01c34fd74b1832e414f869dd9228b1c2','0329a803498ed8dcd7f299a33c4ef777','230030c3ad27bdf508fc0a9c484e1e49']"

   strings:
      $hex_string = { 02006675636f6d69700000000000000000003020000031200000000000000000000000d0800740000000000000000000000006000000050002006675636f6d69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
