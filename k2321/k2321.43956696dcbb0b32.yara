
rule k2321_43956696dcbb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.43956696dcbb0b32"
     cluster="k2321.43956696dcbb0b32"
     cluster_size="24"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy shyape"
     md5_hashes="['047c96c7fa1b49a388b1e12fca4c662f','1b2aa2e5f50c523b986f9fa11efe77bc','bf9709775d875c311b24898d586bc836']"

   strings:
      $hex_string = { 982e458bc37b1e36d6abf5de85737f60b09724d22f1fd1921af06827c8da211b5c9aba162379fe72dd58f8ae772cf4d77767bbd178a0754c43cf8949adfc9b93 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
