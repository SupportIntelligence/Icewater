
rule k3f7_039d93c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.039d93c9c8000b12"
     cluster="k3f7.039d93c9c8000b12"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['19664561f77880fd04830021b217dbff','1a3893f57bb7ed7c92ccb8381de1f80b','c5021c5b664c257554a427c09b6a2caa']"

   strings:
      $hex_string = { 456c656d656e747342795461674e616d6528226865616422295b305d2e617070656e644368696c642863297d76617220662c673b632e737570706f7274733d7b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
