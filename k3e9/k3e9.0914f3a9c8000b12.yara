
rule k3e9_0914f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0914f3a9c8000b12"
     cluster="k3e9.0914f3a9c8000b12"
     cluster_size="546"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['01bdb84e67f4752421e27405fb6655cb','026e662664293966896d4b7477972208','1b76d2a68bacfa7daa04bd6b316308af']"

   strings:
      $hex_string = { 57548d51d47d4f3481e86cfeacad4aa9f9870651de28041a3a5399106442a369a090490c268a120517218d000874e3a5a432914465d0192b622ec08c7f89fad6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
