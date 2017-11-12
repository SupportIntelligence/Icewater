
rule n3e9_51972ec9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.51972ec9c8000932"
     cluster="n3e9.51972ec9c8000932"
     cluster_size="9776"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="banker shiz backdoor"
     md5_hashes="['0004dcb03da56baed7ca0a2ea33d6edb','00145afced96b98e854b4fb1ebb8c1ea','01403a00675f46a685e197825ed5fde3']"

   strings:
      $hex_string = { 301631c331d131fb312732093328333e33d733fb3340344f34b434e13433354d35633587358e35b435d2352736bc36dc365e37c23721389438a738d53807392f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
