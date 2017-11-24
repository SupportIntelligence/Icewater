
rule m2377_6b1e3ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.6b1e3ec1c8000b12"
     cluster="m2377.6b1e3ec1c8000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['135fd4cb5385288154b3387ce42b5e4f','89c9698f62aa152ee1fb49a7ed72afd4','e297e7a3eb32bdeec5cd97a121a3e22d']"

   strings:
      $hex_string = { 4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c6566743a202d353070783b207a2d696e6465783a2031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
