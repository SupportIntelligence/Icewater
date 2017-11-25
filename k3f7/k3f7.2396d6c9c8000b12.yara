
rule k3f7_2396d6c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2396d6c9c8000b12"
     cluster="k3f7.2396d6c9c8000b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['1d7327b51327eb768064ffe2f8d24b17','7685b3e29c6c18ca8b9f6ec9da0827ff','92a02da8b9d09f0baca42de87c75a278']"

   strings:
      $hex_string = { 456c656d656e747342795461674e616d6528226865616422295b305d2e617070656e644368696c642863297d76617220662c673b632e737570706f7274733d7b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
