
rule m3f7_419c16c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.419c16c9c8000932"
     cluster="m3f7.419c16c9c8000932"
     cluster_size="28"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['07547facfdb15dd07b3b28bf27fd0d3b','20ab418877334ef8e4ded09b705a4a12','b00140110a03d4dce86440ee119e1cd6']"

   strings:
      $hex_string = { 77365a5568754c7a3769696346744e78424f4757305569386c766e586c7a784b4534385476487374794c49466854775244774b7032326170793d73302d642720 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
