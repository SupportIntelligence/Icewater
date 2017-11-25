
rule m3e9_16db48a4a16e50ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16db48a4a16e50ba"
     cluster="m3e9.16db48a4a16e50ba"
     cluster_size="91"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup razy zbot"
     md5_hashes="['00bdd0c154f63a37524450ded6cee1af','029939e6c1c829b6f8e9f9c355a0ff3d','5b535e4d8ff193974b30ae6c637d6684']"

   strings:
      $hex_string = { 988e6723b4826b27b0865f2bacfa631fa85e5713c4525b77bf564f7bbb4a536fb7ee4783d3e24b87cfe63f8bcbda437fc7fe3773e3f23b97dff62f9bdbea338f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
