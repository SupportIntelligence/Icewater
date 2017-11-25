
rule m2377_358b7ec1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.358b7ec1c4000b32"
     cluster="m2377.358b7ec1c4000b32"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['30c218efada882626b4906ea5b3980a6','5bf4c31f98f73f363b55f459133e2663','d5c3e4f8e3548efd1e3d7d104d41e289']"

   strings:
      $hex_string = { 3a5f6c6f666d61696e2e676574456c656d656e7428272e6963652d70726576696f757327297d20293b0a0909096f626a6563742e73746172742820302c205f6c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
