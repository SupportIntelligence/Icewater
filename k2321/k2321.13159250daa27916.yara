
rule k2321_13159250daa27916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13159250daa27916"
     cluster="k2321.13159250daa27916"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['213acca54393239263a0099e5f9cdde3','3069e8ac072f7d669951d2b316c5d08b','bee5b2ab22745531a917c8835c5a9959']"

   strings:
      $hex_string = { b8e2d8ed139b944adcd377251eaf547a201207938a637cf86e252b437d090c5e37b02a0e6f80863a8feeb7bc46fd857fc656b2d6b5d5cd7e3d5cad1c2eba9d70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
