
rule m3f7_53e92002580d51b6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.53e92002580d51b6"
     cluster="m3f7.53e92002580d51b6"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['334dc33bac99e8b0cf705077ad6b8697','4d5af6752ee9b3a0cf8dbfadb4b03710','aa76e35398fd23db4e2264c7a559ecb1']"

   strings:
      $hex_string = { 37434246363331464133393845383846353339423142443745433436314132303439433134304135373930323344353643353535453230463342323841344644 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
