
rule k3e9_091af3a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.091af3a9c8000932"
     cluster="k3e9.091af3a9c8000932"
     cluster_size="78"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['06812fea0a83f322aa527f704ba24f09','06f59ff9ccc745b73a0d722dd4836a0e','9884be86cf3b093c23ac3bbf243b7ec8']"

   strings:
      $hex_string = { 57548d51d47d4f3481e86cfeacad4aa9f9870651de28041a3a5399106442a369a090490c268a120517218d000874e3a5a432914465d0192b622ec08c7f89fad6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
