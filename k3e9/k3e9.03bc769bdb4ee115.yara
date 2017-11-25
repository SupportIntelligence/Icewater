
rule k3e9_03bc769bdb4ee115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.03bc769bdb4ee115"
     cluster="k3e9.03bc769bdb4ee115"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart backdoor peed"
     md5_hashes="['70856f15bea668449b0d7f4c68348447','9b3a29d53849afa1c7f73780d268efbb','fad8878fe335a9f315ffdf5f442bc3d2']"

   strings:
      $hex_string = { 12e78bda2cdb7fa66e23f370795c9f59919944ce8a41d6d050d46d986b2446a08e0a4dd0417a0e9ed6183aa169dc7856161c855991a0ba393c62875be414efc9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
