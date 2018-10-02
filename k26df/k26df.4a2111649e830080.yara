
rule k26df_4a2111649e830080
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26df.4a2111649e830080"
     cluster="k26df.4a2111649e830080"
     cluster_size="1857"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nsis adload swbundler"
     md5_hashes="['c090ef5a0f70692611be5f220b28b5c992b6021e','e3a9c1a24202195aae0e92f91734d9b33e0da158','845a18b9b35c5d711c360d1f7cdbfefe88c41b81']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26df.4a2111649e830080"

   strings:
      $hex_string = { e030802c0001e032802c0001e033802c0072006f0000004100420043004400450046004700480049004a004b004c004d004e004f005000510052005300540055 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
