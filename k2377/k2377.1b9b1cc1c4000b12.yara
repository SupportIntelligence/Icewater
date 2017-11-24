
rule k2377_1b9b1cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.1b9b1cc1c4000b12"
     cluster="k2377.1b9b1cc1c4000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html redirme bmhwfh"
     md5_hashes="['27b2ee1da6cc5b295b7112991e553e17','28cb6ebb725eab2f887008ed7bfaf90a','82bba1d06eab697fec540237f6c14321']"

   strings:
      $hex_string = { 7b7d3b242e746d706c3d66756e6374696f6e206528612c63297b76617220643d212f5c572f2e746573742861293f625b615d3d625b615d7c7c6528646f63756d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
