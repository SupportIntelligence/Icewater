
rule n3f8_119992e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.119992e9c8000b32"
     cluster="n3f8.119992e9c8000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adlibrary androidos bankbot"
     md5_hashes="['53f7544c9c335bc34b7301926ab7827b369f155f','83d7aa259cb8a9c83730a23a27c6d4e5ddafd007','abdc8e7883874ba2d3d8ecf514bd8d918b9381c4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.119992e9c8000b32"

   strings:
      $hex_string = { 73244e6f74466f756e64457863657074696f6e3b00254c616e64726f69642f636f6e74656e742f7265732f5265736f7572636573245468656d653b001f4c616e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
