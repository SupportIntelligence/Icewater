
rule k3e9_0998f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0998f3a9c8000b32"
     cluster="k3e9.0998f3a9c8000b32"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['0adfe235a7edbf008a9b62e52d2b45e4','93a68105fb8aff2f8fd28eba10051d7b','fe9a2e88b95af2ecbadde54e2c5ed361']"

   strings:
      $hex_string = { 57548d51d47d4f3481e86cfeacad4aa9f9870651de28041a3a5399106442a369a090490c268a120517218d000874e3a5a432914465d0192b622ec08c7f89fad6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
