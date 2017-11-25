
rule m3e9_16cb4a14716e466e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16cb4a14716e466e"
     cluster="m3e9.16cb4a14716e466e"
     cluster_size="140"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup kazy zbot"
     md5_hashes="['015db3db175510b2a4f6fac01b641359','056c78a428697b2c7f14032fc717b1b6','3911473a6aeb84e7f00ea455a8706e03']"

   strings:
      $hex_string = { 988e6723b4826b27b0865f2bacfa631fa85e5713c4525b77bf564f7bbb4a536fb7ee4783d3e24b87cfe63f8bcbda437fc7fe3773e3f23b97dff62f9bdbea338f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
