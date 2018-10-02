
rule k2319_29129eb9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29129eb9caa00b32"
     cluster="k2319.29129eb9caa00b32"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b8adb26999e7feed306c3158b7c8f30dd4c40e25','fbae80f6b17fcda6003f90cba9de9d7a1120966f','ecf37e596da6ab21ae19c39e96ce06ade7e3c519']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29129eb9caa00b32"

   strings:
      $hex_string = { 3245323f38333a28307845312c3078313730292929627265616b7d3b666f72287661722059385220696e206d33563852297b6966285938522e6c656e6774683d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
