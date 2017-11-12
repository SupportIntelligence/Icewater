
rule k3e9_299df3a9c8000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.299df3a9c8000916"
     cluster="k3e9.299df3a9c8000916"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor tofsee injector"
     md5_hashes="['93e598655464113aa87c7c25a881b4c8','c0a9f4219e9ec70f5924b01e7f00fb3d','d5a4b644d7310d30d8c020170bc80fb3']"

   strings:
      $hex_string = { 57548d51d47d4f3481e86cfeacad4aa9f9870651de28041a3a5399106442a369a090490c268a120517218d000874e3a5a432914465d0192b622ec08c7f89fad6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
