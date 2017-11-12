
rule o3e9_0b3158e6de926bb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b3158e6de926bb2"
     cluster="o3e9.0b3158e6de926bb2"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster malicious browsefox"
     md5_hashes="['18525f4b03bc544f9e9459a6a91ee871','1bae8502944ff6dcd1db93175b5f8074','f1d8a381b2b7593336be66c0dfaa9b3d']"

   strings:
      $hex_string = { 3a57b44b27df6f1225d5d977bdc2b081e98b42822cb6659e00dd4e51c54afdbe0f6d9cad86a593aba3635808e3fc8de89a22a78753a97ec09d498444d33c2002 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
