
rule n3f8_119d12e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.119d12e9c8000b12"
     cluster="n3f8.119d12e9c8000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bankbot adlibrary androidos"
     md5_hashes="['85f3cfa5f6a4f9c2a5c331f53061f8f74b04ae97','14f77be863bb663df1902f51f44b820490c8daca','0df2a21a6bafa56da6a6679f4b2a3ccf9546c0d2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.119d12e9c8000b12"

   strings:
      $hex_string = { 73244e6f74466f756e64457863657074696f6e3b00254c616e64726f69642f636f6e74656e742f7265732f5265736f7572636573245468656d653b001f4c616e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
