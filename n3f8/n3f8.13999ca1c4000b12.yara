
rule n3f8_13999ca1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.13999ca1c4000b12"
     cluster="n3f8.13999ca1c4000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bankbot adlibrary androidos"
     md5_hashes="['241d8147174f55b39dd4f25d69cdb6ec03d12cfd','758940772f9ff6008a3dc899de439e332929dbf8','a87283ac2352225c4621ee2bf1051402afcf914d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.13999ca1c4000b12"

   strings:
      $hex_string = { 73244e6f74466f756e64457863657074696f6e3b00254c616e64726f69642f636f6e74656e742f7265732f5265736f7572636573245468656d653b001f4c616e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
