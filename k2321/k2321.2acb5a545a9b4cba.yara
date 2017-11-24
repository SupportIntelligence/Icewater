
rule k2321_2acb5a545a9b4cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2acb5a545a9b4cba"
     cluster="k2321.2acb5a545a9b4cba"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['0741fa02668da9a0f26dc0153c93b129','11b508de4120a84803c52f678cb19c98','f89b3b5f8fbf42e60f3358b386217af1']"

   strings:
      $hex_string = { bf9a8f1e8b17702e5fcc44e312875142ad781fe4305923aa75a43401fe4186f9ee8c9fed350d0f3b4520e8ac77397327c36283b58e7f0049ef2c268e53b8d846 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
