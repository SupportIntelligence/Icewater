
rule m2377_7919304bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.7919304bc6200b12"
     cluster="m2377.7919304bc6200b12"
     cluster_size="35"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html iframe"
     md5_hashes="['08eec393191e7c839b5a2c5bcca08edf','0a71b246e5535fd3df7b31cd12bfaa4e','66305045172e1ff69580b0da7d642568']"

   strings:
      $hex_string = { 35393032383136433434334646414139443831463732333439444536433139373539324636434237314135413538303642443045313534323345363736323038 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
