
rule k2319_181616b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181616b9caa00b12"
     cluster="k2319.181616b9caa00b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9123f249d04665a71ea52e71345737bd2b682d8d','04fb06d86dbbc7353b75a993bb077cfb54bf879e','dc2732865a9781da2bf68c67076e20688ec4e2c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181616b9caa00b12"

   strings:
      $hex_string = { 3b7661722047397335623d7b27553162273a66756e6374696f6e28442c412c6b297b72657475726e20447c417c6b3b7d2c27703879273a224974222c27533079 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
