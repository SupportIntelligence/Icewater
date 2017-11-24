
rule k3e9_2396e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2396e448c0000b12"
     cluster="k3e9.2396e448c0000b12"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol fdld dropped"
     md5_hashes="['0fc39a07bc630b51b74d7e52cca612f3','2fe7b1cd35e3d59216f3523dd4dff62d','d6907683c654eb1a4b239b4d44f3d85f']"

   strings:
      $hex_string = { 9d16848f73c29f79325e51bdf2f13ff955c77f6cac43e7c09545d4d90446fcad894718a47e39b24258698e71bb2a73d6cf971f86f0adf3e5bebc85744a2e4e76 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
