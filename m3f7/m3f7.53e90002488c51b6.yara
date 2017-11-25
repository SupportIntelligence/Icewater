
rule m3f7_53e90002488c51b6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.53e90002488c51b6"
     cluster="m3f7.53e90002488c51b6"
     cluster_size="16"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['06a54667ac4b8fd01920343741480188','12261026d01ed5e33e177d7b17fb786f','f2c1cf6db00830712fcd8a4354e01c04']"

   strings:
      $hex_string = { 37434246363331464133393845383846353339423142443745433436314132303439433134304135373930323344353643353535453230463342323841344644 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
