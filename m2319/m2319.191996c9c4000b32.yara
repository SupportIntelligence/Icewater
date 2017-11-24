
rule m2319_191996c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.191996c9c4000b32"
     cluster="m2319.191996c9c4000b32"
     cluster_size="10"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['2ecb105f07158516cac69cb1a083909d','40a0218b69e9ac3a56095f7182324748','f35c500526ec69ef8676899e7d79b461']"

   strings:
      $hex_string = { 4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c6566743a202d353070783b207a2d696e6465783a2031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
