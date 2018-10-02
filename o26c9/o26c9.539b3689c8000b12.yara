
rule o26c9_539b3689c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c9.539b3689c8000b12"
     cluster="o26c9.539b3689c8000b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious unsafe badfile"
     md5_hashes="['a7504f836a734e72af76a0493f4494208e8ffccc','84345bd2aba5f029c0f424f0b4d7a334f3515ca9','458751cc6fc9263189037da5e80fdf6abaa71311']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c9.539b3689c8000b12"

   strings:
      $hex_string = { bf3a7af76694913233a22643f6279b10a3ca2d3b9d76d7587b6d31db1122d31efbbd740fbb59d983d852726ad2ddf2ee8762696ea8f98d65088be92c1c5def02 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
