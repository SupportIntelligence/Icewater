
rule k3ed_0ec9547ac8156c56
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.0ec9547ac8156c56"
     cluster="k3ed.0ec9547ac8156c56"
     cluster_size="4"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['680e9519af8dbfcd4e9a7c3aaa94394e','9ebd9d83aa4f826b72f1dbb9a3107ea5','e84dd203f000c419c1e82e057146ab8e']"

   strings:
      $hex_string = { 26bef36c01660f3c0bc0e1e6bcea8efd4af623e99aa9b175bb8c6e4bb6aea1fe69d38fcc2d8899361b7b8d541ae76fcdc12c81d75ada9f33d8646d62420a5ba7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
