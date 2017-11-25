
rule k41a_1bb34ecfcf98f131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k41a.1bb34ecfcf98f131"
     cluster="k41a.1bb34ecfcf98f131"
     cluster_size="107"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="swiftbrowse browsefox yotoon"
     md5_hashes="['030869730c1d468fefbdf83b9fceed31','037ab994538e5b11d697c12131d5915e','2a2cf5ef213e1c93d65d13256caa543f']"

   strings:
      $hex_string = { 152c4e3c6a506c0b36a3cf7a0d9c42bc5cf819d560e369e6e22341678c6883762b8f93a32ab57fbe59fba9c9b2268fcaa2f3821b983e919527978661ee5b5d07 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
