
rule k2321_0ec9547ac8146c57
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ec9547ac8146c57"
     cluster="k2321.0ec9547ac8146c57"
     cluster_size="11"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="yunsip zusy backdoor"
     md5_hashes="['21e6c2edaaa79067a6d0de6ad725bc78','33a2ff0a110b5deed98d806c018d9193','ed7bd10679a4764c347289895caca19f']"

   strings:
      $hex_string = { 26bef36c01660f3c0bc0e1e6bcea8efd4af623e99aa9b175bb8c6e4bb6aea1fe69d38fcc2d8899361b7b8d541ae76fcdc12c81d75ada9f33d8646d62420a5ba7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
