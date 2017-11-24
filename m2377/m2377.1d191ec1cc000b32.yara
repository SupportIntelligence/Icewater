
rule m2377_1d191ec1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.1d191ec1cc000b32"
     cluster="m2377.1d191ec1cc000b32"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['013ed87d4a2499701f678c90b7a59623','5fd69b585f7ab8aba81a8edd0b0ba641','ea03dd96d3fb58ab6096f72ee4499670']"

   strings:
      $hex_string = { 4d9aa847345c18b155423eeaae6641d78c8ee68d5262b2bd543c79971b35de28b7cbd1a72eb984c45f9bf73a247282616b3f7e40cc13ed7ad84fa0fa93be315d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
