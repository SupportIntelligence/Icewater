
rule m3f7_4314ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4314ea48c0000b12"
     cluster="m3f7.4314ea48c0000b12"
     cluster_size="160"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nemucod script html"
     md5_hashes="['002470f9c3cf6cae4bd42053840e470b','03ba8e048c8df48e63ce2f161df2a453','19b06b1545695813d77e60dd275d47f9']"

   strings:
      $hex_string = { 722e5f506f707570436f6e66696728646f63756d656e742e676574456c656d656e7442794964282248544d4c322229293b27207461726765743d27636f6e6669 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
