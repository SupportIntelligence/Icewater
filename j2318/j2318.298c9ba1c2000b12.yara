
rule j2318_298c9ba1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.298c9ba1c2000b12"
     cluster="j2318.298c9ba1c2000b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['1ea931210d64077a927c089738aa3a8a','217ed6bd7dc7d6cb5d9852946501fcdc','cfa5f2159162ee7fe8629ab660130e06']"

   strings:
      $hex_string = { 48544d4c205055424c494320222d2f2f5733432f2f4454442048544d4c20342e3031205472616e736974696f6e616c2f2f454e223e0a3c68746d6c206469723d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
