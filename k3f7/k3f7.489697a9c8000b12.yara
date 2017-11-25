
rule k3f7_489697a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.489697a9c8000b12"
     cluster="k3f7.489697a9c8000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector html fakejquery"
     md5_hashes="['1370ed154985f45245d6c471dc27ed97','3eca3e0742d25664b8a94dfde9844eda','dd828be01fc22a6582b6bff66c445d21']"

   strings:
      $hex_string = { 456c656d656e747342795461674e616d6528226865616422295b305d2e617070656e644368696c642863297d76617220662c673b632e737570706f7274733d7b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
