
rule k2318_339e97a9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339e97a9c8800912"
     cluster="k2318.339e97a9c8800912"
     cluster_size="458"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['5acf87e6af472dff0ff360e3b3027463a62e8a4a','3d4526cab5e74f215fcd954d1d8deb3dc7aa67e9','38defb3f7062bd779c6b45ec460247076e2be604']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339e97a9c8800912"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
